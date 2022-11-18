#!/usr/bin/env python3
import os
import json
import csv

RESULTS_DIR = "./nsc_results/"
RESULTS_EXTN = ".json"

COMPILED_RESULTS = "nsc_results.csv"

def main():
    # Walk through all apk dirs, look for .xmls
    results = get_results(RESULTS_DIR)
    pin_apps = set()
    cert_apps = set()
    fn = ['sha256', 'packageName', 'techniqueName', 'pinningFound', 'pins', 'pinsPaths', 'certs', 'certsPaths', 'extra']
    with open(COMPILED_RESULTS, "w") as ouf:
        writer = csv.DictWriter(ouf, delimiter=',', fieldnames=fn, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for result in results:
            with open(result) as inf:
                result = json.load(inf)
            try:
                app_hash = result["app_hash"]
                pack_name = result["package_name"]
                pins = result["pins"]
                certs = result["certs"]
            except KeyError:
                print("Result missing a key:", result)
                continue
            # Overall stats
            app_key = pack_name + "_" + app_hash
            found = False
            if len(pins) > 0:
                pin_apps.add(app_key)
                found = True
            if len(certs) > 0:
                cert_apps.add(app_key)
                found = True
            writer.writerow({'sha256': app_hash,
                            'packageName': pack_name,
                            'techniqueName': 'networkSecurityConfig',
                            'pinningFound': found,
                            'pins': json.dumps(pins),
                            'certs': json.dumps(certs),
                            })
    print("Total pinners:", len(pin_apps), "Total certs:", len(cert_apps), "Total overlap:",
          len(pin_apps.intersection(cert_apps)), "Total cert+pin:", len(pin_apps.union(cert_apps)))

def get_results(path):
    results = []
    # Folders in the apks path
    for i in os.listdir(path):
        result = os.path.join(path, i)
        if i.endswith(RESULTS_EXTN):
            results.append(result)
    return results

# Boilerplate
if __name__ == "__main__":
    main()
