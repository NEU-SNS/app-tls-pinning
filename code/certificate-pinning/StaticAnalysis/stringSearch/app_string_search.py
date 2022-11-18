import json
import os
import r2pipe
import re
import fcntl
import uuid
import argparse
from androguard.core import androconf
from androguard.core.bytecodes.apk import APK
import shutil
import subprocess
from pathlib import Path
import csv
import hashlib
import base64
import zipfile
import glob
from collections import defaultdict


# Strings of interest; could be regex
strings_of_interest_pins = [ "sha(1|256)/[a-zA-Z0-9+/=]{28,64}" ]
strings_of_interest_certs = ["\-\-\-\-\-(BEGIN CERTIFICATE|BEGIN PKCS7)\-\-\-\-\-(([A-Za-z0-9+=/\\\]|\n)(?!BEGIN))+\-\-\-\-\-(END CERTIFICATE|END PKCS7)\-\-\-\-\-"]

certificate_extensions = ["*.cert", "*.crt", "*.pem", "*.der", "*.cer"]

ios_decrypted_paths = ["/net/data/cert-pinning/ios/popular1k-decrypted", "/net/data/cert-pinning/ios/common600/ios-decrypted"]

parser = argparse.ArgumentParser()
parser.add_argument('--path', '-p', help='Path to an Android .APK file or an iOS .IPA file')
args = parser.parse_args()

IOS_APP_EXTN = ".ipa"
ANDROID_APP_EXTN = ".apk"
RESULT_EXTN = ".json"

APKS_DIR = "../../apks/"
RESULTS_DIR = "./string_search_results/"

R2_OPTIONS = ["-e", "bin.cache=true"]

DEBUG_FLAG = False

"""
Entry point for task manager
"""
def process_task(config):
    file_name = config # Config can be extended later, just file name for now
    debug_print("Performing string searches for:" + file_name)
    if file_name.endswith(IOS_APP_EXTN):
        find_ios_pinning(file_name)
    elif file_name.endswith(ANDROID_APP_EXTN):
        apk_file_path = os.path.join(APKS_DIR, file_name)
        if os.path.isfile(apk_file_path):
            return find_android_pinning(apk_file_path)
    else:
        debug_print("Invalid file, not .ipa or .apk!!" + file_name)
    return 0

    # Move this out to the compile results script
    hash = str(get_file_hash(filename)).upper()
    fieldnames = ['OS', 'sha256', 'packageName', 'techniqueName', 'pinningFound', 'certsFound', 'pins', 'pinsPaths', 'certs', 'certsPaths', 'errors', 'extra']
    with open('stringSearchOutput.csv', 'a') as output:
        csvWriter = csv.DictWriter(output, delimiter=',', fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        csvWriter.writerow({'OS': os,
                            'sha256': hash,
                            'packageName': packageName,
                            'techniqueName': 'pinStringSearch',
                            'pinningFound': len(pins) > 0,
                            'pins': json.dumps(pins),
                            'pinsPaths': json.dumps(pinsPaths),
                            'certsFound': len(certs) > 0,
                            'certs': json.dumps(certs),
                            'certsPaths': json.dumps(certsPaths),
                            'errors': json.dumps(errors)
                            })

def find_android_pinning(file_name):
    # Drop the path and .apk
    result_file_name = file_name.split("/")[-1][:-4]
    package_name = result_file_name.split("-")[0]
    package_hash = result_file_name.split("-")[1]
    ram_dir='/dev/shm/' + str(uuid.uuid4())
    this_result = {}
    pins = defaultdict(list)
    certs = defaultdict(list)
    possible_certs = set()
    errors = set()
    create_dir(RESULTS_DIR)
    # Decompile
    try:
        apktool = subprocess.run("apktool d \"" + file_name + "\" -o " +
                    ram_dir, stdout=subprocess.PIPE, shell=True, check=True)
    except subprocess.CalledProcessError:
        errors.add("Unsuccessful decompilation: " + file_name)
    # Analyze all decompiled files using ripgrep
    for p in strings_of_interest_pins:
        rg = subprocess.run("rg \'" + p + "\' --json -o --search-zip "
                + ram_dir + " > " + ram_dir + "/rgOutput.txt",
                stdout=subprocess.PIPE, shell=True)
        with open(ram_dir + "/rgOutput.txt") as rgOutput:
            for line in rgOutput.readlines():
                item = json.loads(line.strip())
                if item["type"] == "match":
                    for match in item["data"]["submatches"]:
                        pin = match["match"]["text"]
                        path_in_apk = reduce_file_name_to_apk_path(
                            item["data"]["path"]["text"])
                        pins[pin].append(path_in_apk)

    for p in strings_of_interest_certs:
        rg = subprocess.run("rg \'" + p + "\' --json -U -o --pcre2 --search-zip"
                + ram_dir + " > " + ram_dir + "/rgOutput.txt",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        with open(ram_dir + "/rgOutput.txt") as rgOutput:
            for line in rgOutput.readlines():
                item = json.loads(line.strip())
                if item["type"] == "match":
                    for match in item["data"]["submatches"]:
                        cert = match["match"]["text"]
                        path_in_apk = reduce_file_name_to_apk_path(
                            item["data"]["path"]["text"])
                        certs[cert].append(path_in_apk)

    # Analyze native libraries using libradare2
    for path in Path(ram_dir).rglob('*.so'):
        so_filename = str(path.absolute())
        r = r2pipe.open(so_filename, R2_OPTIONS)
        # We don't really need to do this, but this prevents the next command
        # from hanging for certain binaries, apparently.
        bin_info = json.loads(r.cmd('iIj'))
        json_strings = json.loads(r.cmd('izj'))
        for string in json_strings:
            s = string['string']
            for pin in find_signals(s, strings_of_interest_pins):
                path_in_apk = reduce_file_name_to_apk_path(so_filename)
                pins[pin].append(path_in_apk)

            for cert in find_signals(s, strings_of_interest_certs):
                path_in_apk = reduce_file_name_to_apk_path(so_filename)
                certs[cert].append(path_in_apk)
        r.quit()

    for p in certificate_extensions:
        for path in Path(ram_dir).rglob(p):
            cert_filename = str(path.absolute())
            path_in_apk = reduce_file_name_to_apk_path(cert_filename)
            with open(cert_filename, 'rb') as cF:
                cert = base64.b64encode(cF.read()).decode()
                certs[cert].append(path_in_apk)
            possible_certs.add(path_in_apk)
    shutil.rmtree(ram_dir, ignore_errors=True)

    result_file = RESULTS_DIR + result_file_name + RESULT_EXTN
    # Write info about the apk
    this_result["package_name"] = package_name
    this_result["package_hash"] = package_hash
    this_result["platform"] = "Android"
    # Construct things we want to save
    if len(pins) > 0:
        this_result["pins"] = pins
    if len(certs) > 0:
        this_result["certs"] = certs
    if len(possible_certs) > 0:
        this_result["possible_certs"] = list(possible_certs)
    if len(errors) > 0:
        this_result["errors"] = list(errors)
    with open(result_file, "w") as ouf:
        json.dump(this_result, sort_keys=True, indent=2, fp=ouf)
    if len(certs) > 0 or len(pins) > 0 or len(possible_certs) > 0:
        return 1
    return 0


def reduce_file_name_to_apk_path(file_name):
    # TMP DIR of the format /dev/shm/UUID/whatever_important.
    # Save this last part
    return "/".join(file_name.split("/")[4:])

def find_ios_pinning(file_name):
    debug_print("THIS FUNCTION IS BROKEN!!!!")
    os = "iOS"
    # First check if we have a decompiled app or binary for it
    ipa_archive = zipfile.ZipFile(filename, 'r')
    binaryName = None
    packageName = None
    decryptedPath = None
    try:
        for x in ipa_archive.namelist():
            if "Payload/" in x and ".app" in x:
                binaryName = x.split("Payload/", 1)[1].split(".app", 1)[0]
                break
        metadata = ipa_archive.read('iTunesMetadata.plist')
        match = re.search('<key>softwareVersionBundleId<\/key>\n\t<string>(.*)<\/string>', metadata.decode(),
                          re.IGNORECASE)
        packageName = match.group(1)
    # Make this exception more specific
    except:
        pass

        for dp in ios_decrypted_paths:
            processed = glob.glob(dp + "/*")
            if dp + "/" + binaryName in processed:
                decryptedPath = dp + "/" + binaryName
            elif dp + "/" + packageName + ".ipa" in processed:
                decryptedPath = dp + "/" + packageName + ".ipa"
                filename = dp + "/" + packageName + ".ipa"

        # Decompile
        with zipfile.ZipFile(filename, 'r') as zip_ref:
            zip_ref.extractall(TEMPDIR)

        # Analyze all decompiled files using ripgrep
        for p in strings_of_interest_pins:
            rg = subprocess.run(
                "rg \'" + p + "\' --json -o --search-zip " + TEMPDIR + " > " + TEMPDIR + "/rgOutput.txt",
                stdout=subprocess.PIPE,
                shell=True)
            with open(TEMPDIR + "/rgOutput.txt") as rgOutput:
                for line in rgOutput.readlines():
                    item = json.loads(line.strip())
                    if item["type"] == "match":
                        for match in item["data"]["submatches"]:
                            pinsPaths.append(item["data"]["path"]["text"].split("/cert-pinning")[1])
                            pins.append(match["match"]["text"])

        for p in strings_of_interest_certs:
            rg = subprocess.run(
                "rg \'" + p + "\' --json -U -o --pcre2 --search-zip " + TEMPDIR + " > " + TEMPDIR + "/rgOutput.txt",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=True)
            with open(TEMPDIR + "/rgOutput.txt") as rgOutput:
                for line in rgOutput.readlines():
                    item = json.loads(line.strip())
                    if item["type"] == "match":
                        for match in item["data"]["submatches"]:
                            certsPaths.append(item["data"]["path"]["text"].split("/cert-pinning")[1])
                            certs.append(match["match"]["text"])

        # Analyze native libraries using libradare2
        if decryptedPath is not None:
            if ".ipa" in decryptedPath:
                ep = TEMPDIR + "/Payload/" + binaryName + ".app" + "/" + binaryName
            else:
                ep = decryptedPath
            r = r2pipe.open(ep, R2_OPTIONS)
            # We don't really need to do this, but this prevents the next command
            # from hanging for certain binaries, apparently.
            bin_info = json.loads(r.cmd('iIj'))
            json_strings = json.loads(r.cmd('izj'))
            for string in json_strings:
                s = string['string']
                signals = find_signals(s, strings_of_interest_pins)
                for signal in signals:
                    pins.append(signal)
                    pinsPaths.append(ep)

                signals = find_signals(s, strings_of_interest_certs)
                for signal in signals:
                    certs.append(signal)
                    certsPaths.append(ep)
            r.quit()

        # Analyze additional certificate paths, if any
        additional_paths = ["*.cert", "*.crt", "*.pem", "*.der", "*.cer"]
        for p in additional_paths:
            for path in Path(TEMPDIR).rglob(p):
                cert_filename = str(path.absolute())
                with open(cert_filename, 'rb') as cF:
                    certs.append(base64.b64encode(cF.read()).decode())
                certsPaths.append(cert_filename.split("/cert-pinning")[1])


def create_dir(path):
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except FileExistsError:
            pass

def get_file_hash(path):
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def find_signals(s, strings_of_interest):
    signals = []
    for string_of_interest in strings_of_interest:
        search = re.finditer(string_of_interest, s)
        for each_match in search:
            signals.append(each_match[0])
    return signals

def debug_print(m):
    if DEBUG_FLAG:
        print(m)

if __name__ == "__main__":
    main(args.path)
