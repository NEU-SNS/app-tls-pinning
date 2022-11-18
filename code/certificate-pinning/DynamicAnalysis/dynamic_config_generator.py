#!/usr/bin/env python3
import csv
import sys
import json
import os
import re
import multiprocessing
from androguard.core.bytecodes.apk import APK

# Sinas csv with path to pin mappings
CONFIGURATION_FILE = "./dynamic_config.json"
MCG_RESULTS = "./mcg_results/"
MCG_RESULT_EXTN = ".json"
APKS_DIR = "../apks/"
APK_EXTN = ".apk"

OMIT_LIST = "./omit_list.txt"

ACTIVITY_REGEX = re.compile("L.*?;")

INTERNET_PERMISSION = "android.permission.INTERNET"
NETWORK_STATE_PERMISSION = "android.permission.ACCESS_NETWORK_STATE"

def main():
    if len(sys.argv) < 2:
        print("Please provide a result CSV in the expected format.")
        return
    else:
        # The result csvs we've generated from different types of static tests
        # Results rows:
        # sha256, packageName, techniqueName, pinningFound, pins,
        # pinsPaths, certs, certsPaths, extra
        result_files = sys.argv[1:]
    # Set up the structure for configuration file
    config = []
    omit_map = get_hashes_to_skip()
    omited = 0
    results_to_process, fail_apks = get_results_to_process(result_files)
    entry_point_map = get_entry_points_found(results_to_process, omit_map)
    matched = 0
    for hash, result in results_to_process.items():
        hash = hash.upper() # Just to be sure, its already supposed to be upper.
        if hash in omit_map:
            omited += 1
            continue
        config_entry = {}
        if hash in entry_point_map:
            matched += 1
            config_entry["target_intents"] = entry_point_map[hash]
        config_entry["app_hash"] = hash
        config_entry["package_name"] = result["packageName"]
        config.append(config_entry)
    with open(CONFIGURATION_FILE, "w") as ouf:
        json.dump(config, fp=ouf, sort_keys=True, indent=2)
    print("Configs written:", len(config), "MCGs matched:", str(matched), \
            "APKs omited:", str(omited))

def filter_apks_with_internet_permission(apks):
    ret_dict = {}
    worker_pool = multiprocessing.Pool()
    res = worker_pool.map_async(check_permissions, apks.items())
    for i in res.get():
        if i is not None:
            apk_hash, apk_info = i
            ret_dict[apk_hash] = apk_info
    worker_pool.close()
    worker_pool.join()
    return ret_dict

def check_permissions(apk):
    apk_hash, apk_info = apk
    apk_file = APKS_DIR + apk_hash + APK_EXTN
    if os.path.isfile(apk_file):
        # Although inefficient to do this twice, we have to.
        a = APK(apk_file, raw=False)
        permissions = a.get_permissions()
        if INTERNET_PERMISSION in permissions and \
                NETWORK_STATE_PERMISSION in permissions:
            return (apk_hash, apk_info)
    return None

def get_hashes_to_skip():
    ret_lst = set()
    if os.path.isfile(OMIT_LIST):
        with open(OMIT_LIST) as inf:
            for l in inf:
                ret_lst.add(l.strip().upper())
        return ret_lst
    else:
        return set()

def get_results_to_process(result_files):
    # Map from hash to result row, just in case I need fast lookups for some reason
    to_process = {}
    missed_apks = {}
    for result_file in result_files:
        with open(result_file) as inf:
            reader = csv.DictReader(inf, quoting=csv.QUOTE_NONE)
            for row in reader:
                hash = row["sha256"].upper()
                if row["pinningFound"].lower() == "true":
                    to_process[hash] = row
                elif row["pinningFound"].lower() == "false":
                    missed_apks[hash] = row
    for d in to_process.keys():
        if d in missed_apks:
            del missed_apks[d]
    return to_process, missed_apks

def get_entry_points_found(apks_to_process, omit_map):
    # Map from apk_hash to list of entries
    entry_point_map = {}
    mcg_results = get_files_with_ending(MCG_RESULTS, MCG_RESULT_EXTN)
    for result_file in mcg_results:
        apk_hash = result_file.split("/")[-1][:-5].upper()
        if apk_hash not in apks_to_process or apk_hash in omit_map:
            continue
        # Have to have this to get the set of activities to match with possible
        # entry points found with MCG
        apk_file = APKS_DIR + apk_hash + APK_EXTN
        if os.path.isfile(apk_file):
            a = APK(apk_file, raw=False)
            with open(result_file) as inf:
                mcg_result = json.load(inf)
                intents = set()
                # Convert result to intent list
                for matches in map(ACTIVITY_REGEX.findall, mcg_result.keys()):
                    for match in matches:
                        match = match.replace("/", ".") # Replace path to activity type name
                        match = match[1:-1] # Drop the 'L' and ';'
                        match = match.split("$")[0] # Drop the function
                        intents.add(match)
                overlap = set(intents).intersection(set(a.get_activities()))
                matched_intents = []
                for activity in overlap:
                    intent_filter = a.get_intent_filters("activity", activity)
                    keys = intent_filter.keys()
                    if "data" not in keys and "action" in keys:
                        entry = {}
                        entry["activity"] = activity
                        entry["action"] = intent_filter["action"]
                        matched_intents.append(entry)
                entry_point_map[apk_hash] = matched_intents
    return entry_point_map

def get_files_with_ending(path, ending):
    files_found = []
    for i, _, v in os.walk(path):
        for j in v:
            if j.endswith(ending):
                files_found.append(i + "/" + j)
    return files_found

# Boilerplate
if __name__ == "__main__":
    main()
