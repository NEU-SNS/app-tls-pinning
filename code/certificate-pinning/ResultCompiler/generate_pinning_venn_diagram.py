#!/usr/bin/env python3
import matplotlib
matplotlib.use('Agg')
import venn
import sys
import csv
csv.field_size_limit(sys.maxsize)
from collections import defaultdict

VENN_OUTPUT_FILE = "certificate_pinning_venn.pdf"

NSC_RESULT = "./csvs/NSC_RESULT.csv"
STRING_RESULT = "./csvs/STRING_SEARCH_RESULT.csv"
TRUST_RESULT = "./csvs/TRUST_MANAGER_RESULT.csv"
DYNAMIC_RESULT = "./csvs/DYNAMIC_RESULT.csv"

MASTER_RESULT = "./csvs/MASTER_RESULT.csv"
# Results rows:
# sha256,packageName,techniqueName,pinningFound,pins,pinsPaths,certs,certsPaths,extra

def main():
    labels, names = get_combined_result_overlaps()
    fig, ax = venn.venn4(labels, names=names)
    fig.savefig(VENN_OUTPUT_FILE, dpi=2000)
    return

def get_combined_result_overlaps():
    results = defaultdict(set)
    with open(MASTER_RESULT) as inf:
        reader = csv.DictReader(inf, quoting=csv.QUOTE_NONE)
        for row in reader:
            if row["pinningFound"].lower() == "true":
                pack_hash = row["packageName"] + "-" + row["sha256"]
                pack_hash = pack_hash.upper().lower()
                if sina_result(row):
                    results["sina"].add(pack_hash)
                else:
                    results[row["techniqueName"]].add(pack_hash)
    print(results.keys())

    r1 = results["sina"]
    r2 = results["pinStringSearch"]
    r3 = results["networkSecurityConfig"]
    r4 = results["dynamicTesting"]
    names = ["Sina: " + str(len(r1)),
            "String: " + str(len(r2)),
            "NSC: " + str(len(r3)),
            "Dynamic: " + str(len(r4))]
    # Sina      = 1000
    # String    = 0100
    # NSC       = 0010
    # Dynamic   = 0001
    print("Dynamic + Sina")
    for i in r1.intersection(r4):
        print(i)
    labels = {
        "1000": len(((r1-r2)-r3)-r4),
        "0100": len(((r2-r1)-r3)-r4),
        "0010": len(((r3-r1)-r2)-r4),
        "0001": len(((r4-r1)-r2)-r3),
        "1100": len((r1.intersection(r2)-r3)-r4),
        "1010": len((r1.intersection(r3)-r2)-r4),
        "1001": len((r1.intersection(r4)-r2)-r3),
        "0110": len((r2.intersection(r3)-r1)-r4),
        "0101": len((r2.intersection(r4)-r1)-r3),
        "0011": len((r3.intersection(r4)-r1)-r2),
        "1110": len((r1.intersection(r2).intersection(r3))-r4),
        "1101": len((r1.intersection(r2).intersection(r4))-r3),
        "1011": len((r1.intersection(r3).intersection(r4))-r2),
        "0111": len((r2.intersection(r3).intersection(r4))-r1),
        "1111": len(r1.intersection(r2).intersection(r3).intersection(r4))
    }
    print("Dynamic only:", ((r4-r1)-r2)-r3)
    return labels, names

def sina_result(row):
    technique = row["techniqueName"]
    if technique == "CertificatePinner" or technique == "trustManager":
        return True
    return False

if __name__ == "__main__":
    main()
