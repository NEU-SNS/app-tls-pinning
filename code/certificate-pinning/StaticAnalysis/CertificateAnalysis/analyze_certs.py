import csv
import sys
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs7 import load_pem_pkcs7_certificates, load_der_pkcs7_certificates
from cryptography.hazmat.primitives import serialization
import base64
from cryptography.x509.oid import NameOID
import re
import os
import glob
from collections import Counter
import hashlib

csv.field_size_limit(sys.maxsize)
uniqueCertsDynamic = set()
certificateSubjectToCertificate = {"dynamic": {}, "static": {}}
uniqueCertsStatic = set()

pins_to_certs = {"sha1": {}, "sha256": {}}
# Add all certificate mappings from pin -> pem cert when possible

# # First do rapid7
# with open('rawData/successPinsRapid7.txt', 'r') as sp_f:
#     for l in sp_f.readlines():
#         items = l.strip().split(",")
#         assert len(items) == 4
#
#         cert = x509.load_pem_x509_certificate(("-----BEGIN CERTIFICATE-----\n" + items[1] + "\n-----END CERTIFICATE-----").encode(),
#                                               default_backend())
#         pins_to_certs["sha1"][items[2]] = cert
#         pins_to_certs["sha256"][items[3]] = cert

# Then do crt.sh ones
crt_sh_certs = glob.glob("certificatesCrawledStatic/*")
for c in crt_sh_certs:
    with open(c, 'rb') as cf:
        cert = x509.load_pem_x509_certificate(cf.read(),
                                              default_backend())

        sha1hash = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        sha1hash = base64.b64encode(hashlib.sha1(sha1hash).digest()).decode()

        sha256hash = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        sha256hash = base64.b64encode(hashlib.sha256(sha256hash).digest()).decode()
        pins_to_certs["sha1"][sha1hash] = cert
        pins_to_certs["sha256"][sha256hash] = cert

# Auxiliary info
package_to_domain_to_ip = {}
for f in ["./rawData/android_sni_ip_mappings.txt", "./rawData/ios_sni_ip_mappings.txt"]:
    with open(f) as sniF:
        for l in sniF.readlines():
            l = l.strip()
            items = l.split("%%%")
            packageName = items[0].rsplit("-", 1)[0]
            if packageName not in package_to_domain_to_ip:
                package_to_domain_to_ip[packageName] = {}

            package_to_domain_to_ip[packageName][items[1]] = items[2]

# GET ALL CERTIFICATES FROM DYNAMIC ANALYSIS (old)
# androidDynamicResults = {}
# iosDynamicResuts = {}
# packageCertificatesDynamic = {"android": {}, "ios": {}}
# for f in ["./rawData/androidDynamicAnalysis.txt", "./rawData/iosDynamicAnalysis.txt"]:
#     with open(f) as rF:
#         for l in rF.readlines():
#             thisAppCerts = set()
#             l = l.strip().split("%%%")
#             if "android" in f:
#                 androidDynamicResults[l[0]] = l[1:]
#             else:
#                 iosDynamicResuts[l[0]] = l[1:]
#
#             certsPaths = []
#             for domain in l[1:]:
#                 if os.path.exists("./certificatesCrawledDynamic/" + package_to_domain_to_ip[l[0]][domain]):
#                     certsPaths.extend(
#                         glob.glob("./certificatesCrawledDynamic/" + package_to_domain_to_ip[l[0]][domain] + "/*"))
#                 elif os.path.exists(
#                         "./certificatesCrawledDynamic/" + domain + "-" + package_to_domain_to_ip[l[0]][domain]):
#                     certsPaths.extend(glob.glob(
#                         "./certificatesCrawledDynamic/" + domain + "-" + package_to_domain_to_ip[l[0]][domain] + "/*"))
#                 else:
#                     print("Could not find a certificate for domain from dynamic analysis")
#
#             for p in certsPaths:
#                 with open(p, 'rb') as cP:
#                     data = cP.read()
#                     uniqueCertsDynamic.add(x509.load_pem_x509_certificate(data, default_backend()).public_bytes(serialization.Encoding.PEM).decode())
#                     try:
#                         thisAppCerts.add(str(x509.load_pem_x509_certificate(data, default_backend()).subject))
#                         certificateSubjectToCertificate["dynamic"][str(x509.load_pem_x509_certificate(data, default_backend()).subject)] = \
#                             x509.load_pem_x509_certificate(data, default_backend())
#                     except:
#                         print("error parsing a certificate entry in dynamic data...")
#
#             if "android" in f and len(thisAppCerts) > 0:
#                 packageCertificatesDynamic["android"][l[0]] = thisAppCerts
#             else:
#                 packageCertificatesDynamic["ios"][l[0]] = thisAppCerts

# GET ALL CERTIFICATES FROM DYNAMIC ANALYSIS (new)
packageCertificatesDynamic = {"android": {}, "ios": {}}
FPP = "FIRST_PARTY_PINNED"
TPP = "THIRD_PARTY_PINNED"
for f in glob.glob('rawData/pinning_results/*.json'):
    with open(f) as rF:
        dataset_type = f.rsplit("/", 1)[1].split("_")[0]
        results = json.load(rF)

        for package_name, pinned_doms in list(results[FPP].items()) + list(results[TPP].items()):
            for domain in pinned_doms:
                if package_name not in packageCertificatesDynamic[dataset_type]:
                    packageCertificatesDynamic[dataset_type][package_name] = set()

                certsPaths = []
                if os.path.exists("./certificatesCrawledDynamic/" + package_to_domain_to_ip[package_name][domain]):
                    certsPaths.extend(
                        glob.glob("./certificatesCrawledDynamic/" + package_to_domain_to_ip[package_name][domain] + "/*"))
                elif os.path.exists(
                        "./certificatesCrawledDynamic/" + domain + "-" + package_to_domain_to_ip[package_name][domain]):
                    certsPaths.extend(glob.glob(
                        "./certificatesCrawledDynamic/" + domain + "-" + package_to_domain_to_ip[package_name][
                            domain] + "/*"))
                else:
                    print("Could not find a certificate for domain from dynamic analysis")

                for p in certsPaths:
                    with open(p, 'rb') as cP:
                        data = cP.read()
                        uniqueCertsDynamic.add(x509.load_pem_x509_certificate(data, default_backend()).public_bytes(
                            serialization.Encoding.PEM).decode())
                        try:
                            packageCertificatesDynamic[dataset_type][package_name].add(str(x509.load_pem_x509_certificate(data, default_backend()).subject))
                            certificateSubjectToCertificate["dynamic"][
                                str(x509.load_pem_x509_certificate(data, default_backend()).subject)] = \
                                x509.load_pem_x509_certificate(data, default_backend())
                        except:
                            print("error parsing a certificate entry in dynamic data...")

# GET ALL CERTIFICATES FROM STATIC ANALYSIS
packageCertificatesStatic = {"android": {}, "ios": {}}
countAllCerts = 0
successAllCerts = 0

pinsFound = set()
pinsUnknown = set()
fieldnames = ['OS', 'sha256', 'packageName', 'techniqueName', 'pinningFound', 'certsFound', 'pins', 'pinsPaths',
              'certs', 'certsPaths', 'errors', 'extra']
for datasetType in [("android", "rawData/androidStaticAnalysis.txt"), ("ios", "rawData/iosStaticAnalysis.txt")]:
    with open(datasetType[1], 'r') as output:
        csvReader = csv.DictReader(output, delimiter=',', fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        for row in csvReader:
            thisAppCerts = set()

            if row['pinningFound'] == "True":
                pins = json.loads(row['pins'])
                for p in pins:
                    cert = None
                    if "sha1/" in p and p.replace("sha1/", "") in pins_to_certs["sha1"]:
                        pinsFound.add(p)
                        cert = pins_to_certs["sha1"][p.replace("sha1/", "")]

                    elif "sha256/" in p and p.replace("sha256/", "") in pins_to_certs["sha256"]:
                        pinsFound.add(p)
                        cert = pins_to_certs["sha256"][p.replace("sha256/", "")]

                    else:
                        pinsUnknown.add(p)

                    if cert is not None:
                        uniqueCertsStatic.add(cert.public_bytes(
                            serialization.Encoding.PEM).decode())
                        thisAppCerts.add(str(cert.subject))
                        certificateSubjectToCertificate["static"][str(cert.subject)] = cert

            if row['certsFound'] == "True":
                certs = json.loads(row['certs'])
                certsPaths = json.loads(row['certsPaths'])
                for i in range(0, len(certs)):
                    countAllCerts += 1
                    c = certs[i]

                    # Each entry itself might contain multiple certs if its PKCS7
                    thisItemCertificates = []

                    # We're dealing with a raw file (.crt, .pem, .der etc.)
                    if "-----BEGIN" not in c:
                        raw_file_bytes = base64.b64decode(c.encode())

                        try:
                            thisItemCertificates.append(x509.load_der_x509_certificate(raw_file_bytes, default_backend()))
                            successAllCerts += 1
                        except Exception as e:
                            try:
                                thisItemCertificates = load_der_pkcs7_certificates(raw_file_bytes)
                                successAllCerts += 1
                            except Exception as e:
                                try:
                                    start = "-----BEGIN CERTIFICATE-----"
                                    end = "-----END CERTIFICATE-----"
                                    pem = start + "\n" + raw_file_bytes.decode() + "\n" + end
                                    thisItemCertificates.append(
                                        x509.load_pem_x509_certificate(pem.encode(), default_backend()))
                                    successAllCerts += 1
                                except Exception as e:
                                    try:
                                        if raw_file_bytes.count(b"KEY-----") >= 1 or raw_file_bytes == b"":
                                            successAllCerts += 1
                                            continue

                                        if raw_file_bytes.count(b"-----BEGIN CERTIFICATE-----") >= 1:
                                            begins = [m.start() for m in re.finditer('-----BEGIN CERTIFICATE-----', raw_file_bytes.decode())]
                                            ends = [m.start() for m in re.finditer('-----END CERTIFICATE-----', raw_file_bytes.decode())]
                                            assert len(begins) == len(ends)
                                            for i in range(0, len(begins)):
                                                # print(raw_file_bytes.decode()[begins[i]:ends[i]+len("-----END CERTIFICATE-----")])
                                                thisItemCertificates.append(
                                                    x509.load_pem_x509_certificate(raw_file_bytes.decode()[begins[i]:ends[i]+len("-----END CERTIFICATE-----")].encode(), default_backend()))
                                            successAllCerts += 1
                                        else:

                                            # We tried our best to parse the certificate, if its still unparsed, can't do better
                                            assert False

                                    except Exception as e:
                                        continue
                                        # print(raw_file_bytes)
                                        # input()

                    # We're dealing with one BEGIN CERT/BEGIN PKCS7 string...
                    else:

                        assert c.count("-----BEGIN") == 1

                        # Try loading PEM in the default way
                        try:
                            thisItemCertificates.append(x509.load_pem_x509_certificate(c.encode(), default_backend()))
                            successAllCerts += 1
                        except Exception as e:
                            # Try fixing literal new lines
                            try:
                                thisItemCertificates.append(x509.load_pem_x509_certificate(c.replace("\\n", "\n").replace("\\r", "\r").encode(), default_backend()))
                                successAllCerts += 1
                            except Exception as e:
                                # Try fixing new lines at front and end
                                try:
                                    thisItemCertificates.append(x509.load_pem_x509_certificate(
                                        c.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n").replace(
                                        "-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----").encode(), default_backend()))
                                    successAllCerts += 1
                                except Exception as e:
                                    # Try loading PKCS7 cert
                                    try:
                                        thisItemCertificates = load_pem_pkcs7_certificates(c.encode())
                                        successAllCerts += 1
                                    except Exception as e:
                                        continue

                    for c_entry in thisItemCertificates:
                        uniqueCertsStatic.add(c_entry.public_bytes(
                            serialization.Encoding.PEM).decode())
                        try:
                            thisAppCerts.add(str(c_entry.subject))
                            certificateSubjectToCertificate["static"][str(c_entry.subject)] = c_entry
                        except:
                            print("error parsing a certificate entry in static data...")

            # print(len(certs), len(appCertsConsistentFormat), len(set(appCertsConsistentFormat)))
            if len(thisAppCerts) > 0:
                packageCertificatesStatic[datasetType[0]][row['packageName']] = thisAppCerts

print("Pins found/unknown", len(pinsFound), len(pinsUnknown))
print("Total unique certificates across all apps (dynamic): ", len(uniqueCertsDynamic))
print("Total unique certificates across all apps (static): ", len(uniqueCertsStatic))
print("How many \"cert\" entries from static data were we able to parse: total/parsed", countAllCerts, successAllCerts)
cert_type = []
expiry_ca = []
expiry_non_ca = []
apps_with_intersction = set()
for datasetType in ["android", "ios"]:
    print(datasetType + " results: ")
    for app in packageCertificatesStatic[datasetType]:
        if app in packageCertificatesDynamic[datasetType]:
            if len(packageCertificatesStatic[datasetType][app].intersection(packageCertificatesDynamic[datasetType][app])) > 0:
                apps_with_intersction.add(datasetType + app)
                # print(app, packageCertificatesStatic[datasetType][app].intersection(packageCertificatesDynamic[datasetType][app]))
                for item in packageCertificatesStatic[datasetType][app].intersection(packageCertificatesDynamic[datasetType][app]):
                    print(item, certificateSubjectToCertificate["dynamic"][item].extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
                    cert_type.append(certificateSubjectToCertificate["static"][item].extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
                    if not certificateSubjectToCertificate["dynamic"][item].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                        print(certificateSubjectToCertificate["dynamic"][item].not_valid_after)
                        print(certificateSubjectToCertificate["static"][item].not_valid_after)
print(Counter(cert_type))
print("Apps for whom we're able to find a match: ", len(apps_with_intersction))
total = 0
for datasetType in ["android", "ios"]:
    for app in packageCertificatesDynamic[datasetType]:
        total += 1
print("Total apps dynamic pinning", total)