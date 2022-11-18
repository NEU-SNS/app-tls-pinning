from collections import defaultdict
import sys
import csv
csv.field_size_limit(sys.maxsize)

def get_result_from_csv(csv_file):
    results = defaultdict(set)
    with open(csv_file) as inf:
        reader = csv.DictReader(inf, quoting=csv.QUOTE_NONE)
        for row in reader:
            if row["pinningFound"].lower() == "true":
                hash = row["sha256"].upper()
                package_name = row["packageName"].lower()
                technique = row["techniqueName"]
                if technique == "CertificatePinner" or technique == "trustManager":
                    results["sina"].add(package_name)
                else:
                    results[technique].add(package_name)
    print(results.keys())
    return results
