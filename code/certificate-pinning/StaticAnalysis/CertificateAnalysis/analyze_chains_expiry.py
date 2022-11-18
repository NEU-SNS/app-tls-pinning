import glob
from subprocess import check_output, CalledProcessError
from collections import Counter

# Expiry of leaf
# baseDirChains = glob.glob("./certificatesCrawled/*")
# for bD in baseDirChains:
#     chainElements = sorted(glob.glob(bD + "/*"))
#     command = "/usr/local/opt/openssl@3/bin/openssl x509 -noout -enddate -in"
#     command += " " + chainElements[0]
#     try:
#         out = check_output(["/bin/sh", "-c", command], stderr=-2)
#     except CalledProcessError as e:
#         out = e.output
#
#     try:
#         print(bD, out.decode().rsplit(":", 1)[1].rsplit(" ", 2)[1])
#     except:
#         continue
# exit(0)

chainsInfo = {}
with open('./rawData/analyze_chains_expiry.txt') as aC:
    for l in aC.readlines():
        l = l.strip().rsplit("/", 1)[1].split(" ", 1)
        chainsInfo[l[0].rsplit("-",1)[0]] = int(l[1])

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

androidDynamicResults = {}
iosDynamicResuts = {}
for f in ["./rawData/androidDynamicAnalysis.txt", "./rawData/iosDynamicAnalysis.txt"]:
    with open(f) as rF:
        for l in rF.readlines():
            l = l.strip().split("%%%")
            if "android" in f:
                androidDynamicResults[l[0]] = l[1:]
            else:
                iosDynamicResuts[l[0]] = l[1:]

for datasetType in [("android", androidDynamicResults), ("ios", iosDynamicResuts)]:
    results = []
    for r in datasetType[1]:
        for d in datasetType[1][r]:
            if d.replace("without-SNI: ", "") in chainsInfo:
                results.append(chainsInfo[d.replace("without-SNI: ", "")])
            else:
                results.append("Unknown")
    print(datasetType[0], Counter(results))