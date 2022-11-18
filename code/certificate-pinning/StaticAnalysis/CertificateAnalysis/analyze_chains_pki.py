import glob
from subprocess import check_output, CalledProcessError
from collections import Counter
import json

# Custom PKI vs Default PKI
# baseDirChains = glob.glob("./certificatesCrawledDynamic/*")
# for bD in baseDirChains:
#     chainElements = sorted(glob.glob(bD + "/*"))
#     command = "/usr/local/opt/openssl@3/bin/openssl verify -no_check_time -CAfile ./rawData/cacert.pem"
#     for x in range(1, len(chainElements)):
#         command += " -untrusted " + chainElements[-x]
#     command += " " + chainElements[0]
#     try:
#         out = check_output(["/bin/sh", "-c", command], stderr=-2)
#     except CalledProcessError as e:
#         out = e.output
#
#     result = "defaultPKI"
#     if b"cert1.pem: OK" not in out:
#         if b"error 18 at 0 depth lookup: self-signed certificate" in out:
#             result = "selfSigned"
#         else:
#             result = "customPKI"
#
#     print(bD, result)
# exit(0)

chainsInfo = {}
with open('./rawData/analyze_chains_pki.txt') as aC:
    for l in aC.readlines():
        l = l.strip().rsplit("/", 1)[1].split(" ", 1)
        chainsInfo[l[0].rsplit("-",1)[0]] = l[1]

# androidSniIP = {}
# iOSSniIP = {}
# for f in ["./rawData/android_sni_ip_mappings.txt", "./rawData/ios_sni_ip_mappings.txt"]:
#     with open(f) as rF:
#         for l in rF.readlines():
#             l = l.strip().split("%%%")
#             if "android" in f:
#                 appName = l[0].split("-")[0]
#                 if appName not in androidSniIP:
#
#                 androidSniIP[] = {l[1]: l[2]}
#             else:
#                 iOSSniIP[l[0].split("-")[0]] = {l[1]: l[2]}
# print(iOSSniIP)

# Gather all pinned domains (old)
# androidDynamicResults = {}
# iosDynamicResuts = {}
# for f in ["./rawData/androidDynamicAnalysis.txt", "./rawData/iosDynamicAnalysis.txt"]:
#     with open(f) as rF:
#         for l in rF.readlines():
#             l = l.strip().split("%%%")
#             if "android" in f:
#                 androidDynamicResults[l[0]] = l[1:]
#             else:
#                 iosDynamicResuts[l[0]] = l[1:]

# Gather all pinned domains (updated)
FPP = "FIRST_PARTY_PINNED"
TPP = "THIRD_PARTY_PINNED"
pinning_results = {"ios" : {}, "android": {}}
result_files = glob.glob('rawData/pinning_results/*.json')
for f in result_files:
    with open(f) as rF:
        dataset_type = f.rsplit("/", 1)[1].split("_")[0]
        results = json.load(rF)

        for package_name, pinned_doms in list(results[FPP].items()) + list(results[TPP].items()):
            for x in pinned_doms:
                if package_name not in pinning_results[dataset_type]:
                    pinning_results[dataset_type][package_name] = set()
                pinning_results[dataset_type][package_name].add(x)

for dataset_type in pinning_results:
    results = []
    for r in pinning_results[dataset_type]:
        for d in pinning_results[dataset_type][r]:
            if d.replace("without-SNI: ", "") in chainsInfo:
                results.append(chainsInfo[d.replace("without-SNI: ", "")])
                if chainsInfo[d.replace("without-SNI: ", "")] == "customPKI":
                    print(d)

                if chainsInfo[d.replace("without-SNI: ", "")] == "selfSigned":
                    print("selfSigned", d)
            else:
                results.append("Unknown")
    print(dataset_type, Counter(results))
