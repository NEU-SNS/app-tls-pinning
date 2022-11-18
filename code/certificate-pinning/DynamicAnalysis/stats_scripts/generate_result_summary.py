#!/usr/bin/env python3
import os
import json
import csv
import sys
from collections import defaultdict

RESULTS_EXTN = ".result"

CLIENT_SUBNET_PREFIX_1 = "10.42.0"
CLIENT_SUBNET_PREFIX_2 = "192.168.2"

def main():
    # Walk through all apk dirs, look for .xmls
    if len(sys.argv) != 2:
        print("Please provide exactly 1 path to process .pcap files from.")
        return
    else:
        tls_res_path = sys.argv[1]

    tls_res_files = get_files_from_path(tls_res_path + '/logs/', RESULTS_EXTN)
    RESULT_SUMMARY_FILE = tls_res_path + "/result_summary.json"
    combined_result = {}
    print("Processing", len(tls_res_files), "files...")
    successful_only = 0
    failed_only = 0
    mixed = 0
    for result in tls_res_files:
        with open(result) as inf:
            result = json.load(inf)
        app_hash = ""
        pack_name = ""
        try:
            app_hash = result["app_hash"]
            pack_name = result["package_name"]
            app_id = pack_name + "-" + app_hash
        except KeyError:
            print("Result missing a key:", result)
            continue
        if "failed_handshakes" in result:
            failed_handshakes = result["failed_handshakes"]
            successful_handshakes = {}
            if "successful_handshakes" in result:
                successful_handshakes = result["successful_handshakes"]
            if len(successful_handshakes) > 0:
                mixed += 1
                combined_result[app_id] = {
                    "failed_handshakes": failed_handshakes,
                    "successful_handshakes": successful_handshakes
                }
            else:
                failed_only += 1
                combined_result[app_id] = {
                    "failed_handshakes": failed_handshakes
                }
        elif "successful_handshakes" in result:
            combined_result[app_id] = {
                "successful_handshakes": result["successful_handshakes"]
            }
            successful_only += 1
    print("Successful only:", successful_only)
    print("Failed only:", failed_only)
    print("Mixed:", mixed)
    print("Writing summary to", RESULT_SUMMARY_FILE)
    # Dump the combined result of all failed handshakes found across pcaps, used to post process and compare results
    with open(RESULT_SUMMARY_FILE, "w") as ouf:
        json.dump(combined_result, fp=ouf, sort_keys=True, indent=2)

def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj

def get_files_from_path(path, extension):
    retset = set()
    for f in os.listdir(path):
        if f.endswith(extension):
            retset.add(path + "/" + f) # Need to track path as well
    return retset

# Boilerplate
if __name__ == "__main__":
    main()
