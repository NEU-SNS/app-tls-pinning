#!/usr/bin/env python3
import os
import json
import xmltodict
import multiprocessing
import ssl
import hashlib
from androguard.core.bytecodes import apk
from androguard.core import androconf
from androguard.core.bytecodes.axml import AXMLPrinter
from collections import OrderedDict
import zipfile

# This dir contains the set of .apks to process, no decompilation necessary.
APKS_DIR = "../../apks/"
RESULTS_DIR = "./nsc_results/"
RESULTS_EXTN = ".json"

# XML Search stuff
NSC_KEY = "{http://schemas.android.com/apk/res/android}networkSecurityConfig"

"""
Entry point for task_manager, calls this with whatever config and this script
handles the rest.
In this instance, we need to know what apk to process, apk paths are constant at
the moment, so we look there and see if its valid and process it and write to
the right result file.
"""
def process_task(config):
    create_dir(RESULTS_DIR)
    # Sanitize config to make sure it has valid options to process
    apk_name = config # We need just that right now, can extend this to be a
                      # dict in the future if needed!
    apk_file_path = os.path.join(APKS_DIR, apk_name)
    if os.path.isfile(apk_file_path):
        return process_apk(apk_file_path)
    else:
        return 0

def create_dir(d):
    if not os.path.exists(d):
        try:
            os.makedirs(d)
        except FileExistsError:
            pass

def process_apk(apk_file):
    print("Finding NSC for:", apk_file)
    apk_name = apk_file.split("/")[-1]
    if apk_name.endswith(".apk"):
        apk_name = apk_name[:-4]
    try:
        parsed_apk = apk.APK(apk_file)
    except zipfile.BadZipFile:
        print("Bad Zip File:", apk_file)
        return 0
    manifest_xml = parsed_apk.get_android_manifest_xml()
    application = manifest_xml.find('application')
    nsc_id = application.get(NSC_KEY)
    if nsc_id is not None:
        # https://github.com/androguard/androguard/blob/6d9f09b15ada11c29777ff9466826eb3813c3209/androguard/cli/entry_points.py#L195
        try:
            nsc_xml = get_xml_from_nsc_id(parsed_apk, nsc_id)
        except ValueError:
            print("Value error processing", apk_file)
            return 0
        except apk.FileNotPresent:
            print("File not present error", apk_file)
            return 0
        parsed_xml = process_parsed_xml(parsed_apk, xmltodict.parse(nsc_xml))
        # Add app data to the parsed xml data
        parsed_xml["package_name"] = parsed_apk.package
        parsed_xml["app_hash"] = get_file_sha256(apk_file)
        results_file = RESULTS_DIR + apk_name + RESULTS_EXTN
        with open(results_file, "w") as ouf:
            json.dump(parsed_xml, sort_keys=True, indent=2, fp=ouf)
        return 1
    return 0

def get_file_sha256(path):
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

def get_xml_from_nsc_id(parsed_apk, nsc_id):
    if nsc_id[0] == "@":
        try:
            nsc_id = int(nsc_id[1:], 16)
        except ValueError:
            print("NSC:", nsc_id, "could not be converted to hex? o.O")
    arscobj = parsed_apk.get_android_resources()
    try:
        nsc_xml = arscobj.get_resource_xml_name(nsc_id)
    except ValueError:
        print("Trying to get nsc xml failed!!")
        raise ValueError
    nsc_lst = []
    for config, entry in arscobj.get_resolved_res_configs(nsc_id):
        nsc_lst.append(entry)
    if len(set(nsc_lst)) > 1:
        print("NSC for this resolves to more than one resource file!")
    nsc_res = nsc_lst[0]
    nsc_raw = parsed_apk.get_file(nsc_res)
    nsc_xml = AXMLPrinter(nsc_raw).get_xml(pretty=False).decode("utf-8")
    return nsc_xml

def get_raw_from_id(parsed_apk, res_id):
    if res_id[0] == "@":
        try:
            res_id = int(res_id[1:], 16)
        except ValueError:
            print("Converting resource ID to hex problem? o.O")
    arscobj = parsed_apk.get_android_resources()
    res_lst = []
    for config, entry in arscobj.get_resolved_res_configs(res_id):
        res_lst.append(entry)
    if len(set(res_lst)) > 1:
        print("Raw resource resolves to more than one resource file!")
    res = res_lst[0]
    cert = parsed_apk.get_file(res)
    try:
        cert = cert.decode("utf-8")
    except UnicodeDecodeError:
        cert = ssl.DER_cert_to_PEM_cert(cert)
    return cert


def process_parsed_xml(parsed_apk, parsed_xml):
    og_parsed = parsed_xml
    if "network-security-config" not in parsed_xml:
        return {"NO_NSC_ERROR": og_parsed}
    parsed_xml = parsed_xml["network-security-config"]
    if not parsed_xml:
        return {"NSC_NONE_ERROR": og_parsed}
    ret_data = {}
    certs = set()
    pins = set()
    # Process base-config
    if "base-config" in parsed_xml:
        bc = parsed_xml["base-config"]
        if type(bc) is list:
            ret_data["BASE_CONFIG_ERROR"] = True
        elif bc is None:
            ret_data["BASE_CONFIG_NONE"] = True
        else:
            if "@cleartextTrafficPermitted" in bc:
                ret_data["base_cleartext"] = bc["@cleartextTrafficPermitted"]
            else:
                ret_data["base_cleartext"] = False # Assuming target is android 9 for now, looking up the apk target in the manifest might be the right way to go!
            if "trust-anchors" in bc:
                ta = bc["trust-anchors"]
                if type(ta) is list:
                    ret_data["BASE_CONFIG_TRUST_ANCHOR_ERROR"] = True
                else:
                    ret_data["base_trust_anchors"], certs_found = process_trust_anchors(parsed_apk, ta)
                    certs.update(certs_found)
    # Process domain-config
    if "domain-config" in parsed_xml:
        ret_data["domain_configs"], certs_found, pins_found = process_domain_configs(parsed_apk, parsed_xml["domain-config"])
        certs.update(certs_found)
        pins.update(pins_found)
    # Process debug-overrides
    if "debug-overrides" in parsed_xml:
        if type(parsed_xml["debug-overrides"]) is list:
            ret_data["DEBUG_OVERRIDES_ERROR"] = True
        else:
            do = parsed_xml["debug-overrides"]
            if do is not None and "trust-anchors" in do:
                ta = do["trust-anchors"]
                if type(ta) is list:
                    ret_data["DEBUG_OVERRIDES_MULTIPLE_TRUST_ANCHOR_ERROR"] = True
                else:
                    # Don't save certs since it only applies to debug builds
                    ret_data["debug_override_trust_anchors"], certs_found = process_trust_anchors(parsed_apk, ta)
                    # Ignore debug certs for now
                    # certs.update(certs_found)
            elif do is None:
                ret_data["DEBUG_OVERRIDES_NONE_ERROR"] = True
            else:
                ret_data["DEBUG_OVERRIDES_EMPTY_ERROR"] = True
    # Adding pins and certs, losing info about what domains these are pinned for at the moment, might need to change later.
    ret_data["certs"] = list(certs)
    ret_data["pins"] = list(pins)
    return ret_data

def process_domain_configs(parsed_apk, dcs):
    dcs = check_get_list(dcs)
    dcs_data = []
    certs = set()
    pins = set()
    for dc in dcs:
        dc_data = {}
        if "domain-config" in dc:
            dc_data["domain_configs"], certs_found, pins_found = process_domain_configs(parsed_apk, dc["domain-config"])
            certs.update(certs_found)
            pins.update(pins_found)
        if "@cleartextTrafficPermitted" in dc:
            dc_data["clear_text_permitted"] = dc["@cleartextTrafficPermitted"]
        else:
            dc_data["clear_text_permitted"] = "MISSING_CTP_ATTRIBUTE"
        # Get trust anchor for this set of domains first
        if "trust-anchors" in dc:
            ta = dc["trust-anchors"]
            if type(ta) is list:
                dc_data["MULTIPLE_TRUST_ANCHOR_ERROR"] = True
            else:
                dc_data["trust_anchors"], certs_found = process_trust_anchors(parsed_apk, ta)
                certs.update(certs_found)
        # Deal with the list of domains
        if "domain" not in dc:
            dc_data["NO_DOMAIN_ERROR"] = True
        else:
            domains = check_get_list(dc["domain"])
        dc_data["domains"] = process_domains(domains)
        # Deal with the pin set:
        if "pin-set" in dc and dc["pin-set"] is not None:
            dc_data["pin_set"], pins_found = process_pin_set(dc["pin-set"])
            pins.update(pins_found)
        dcs_data.append(dc_data)
    return dcs_data, certs, pins

def process_pin_set(ps):
    ret_dict = {}
    if "@expiration" in ps:
        ret_dict["expiration"] = ps["@expiration"]
    else:
        ret_dict["expiration"] = "0000-00-00"
    if "pin" not in ps:
        ret_dict["EMPTY_PIN_SET_ERROR"] = True
        return ret_dict
    pins = ps["pin"]
    pins_list = []
    # All sha256 at the moment, so assuming that...
    for p in pins:
        if type(p) is OrderedDict:
            pins_list.append(p["#text"])
        else:
            pins_list.append(p)
    ret_dict["pins"] = pins_list
    return ret_dict, pins_list

def process_domains(domains):
    ret_dict = {}
    for d in domains:
        flag = False
        if type(d) is OrderedDict:
            if "@includeSubdomains" in d:
                flag = d["@includeSubdomains"]
            if "#text" in d:
                ret_dict[d["#text"]] = {"include_subdomains": flag}
            else:
                print("Weird domain with no domain name, skipping...")
        else:
            ret_dict[d] = {"include_subdomains": False} # Deal with xmltodict base case again
    return ret_dict

def process_trust_anchors(parsed_apk, trust_anchors):
    if trust_anchors is None:
        return None, set()
    certs = check_get_list(trust_anchors["certificates"])
    no_override = set()
    override = set()
    certs_found = set()
    for cert in certs:
        try:
            src = cert["@src"]
            if src[0] == "@":
                src = get_raw_from_id(parsed_apk, src)
                certs_found.add(src)
        except KeyError:
            src = "MISSING_SRC"
        if "@overridePins" in cert and cert["@overridePins"]:
            override.add(src)
        else:
            no_override.add(src)
    return {
        "override_pins": list(override),
        "no_override": list(no_override)
    }, certs_found

def get_files_with_ending(path, ending):
    files_found = []
    for i, _, v in os.walk(path):
        for j in v:
            if j.endswith(ending):
                files_found.append(i + "/" + j)
    return files_found

def check_get_list(i):
    if type(i) is not list:
        return [i]
    return i
