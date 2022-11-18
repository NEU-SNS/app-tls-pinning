#!/usr/bin/env python3
import csv
import json
import itertools
import os
from collections import defaultdict
import sys
sys.path.append("../utils")
import task_variables

# Picking achtungs based on how many processes they can handle.
achtungs = []
achtungs100 = ["achtung02", "achtung03", "achtung04", "achtung05", "achtung06",
    "achtung07", "achtung08", "achtung09", "achtung10", "achtung11",
    "achtung12", "achtung13", "achtung14", "achtung15", "achtung16",
    "achtung17"]
for i in range(0, 2):
    achtungs.extend(achtungs100)
achtungs = ["virabhadra"]
achtungpool = itertools.cycle(achtungs)

# Sinas csv with path to pin mappings
SINA_FILTER = "trust_manager_possible.csv"
USE_SINA_FILTER = False

CONFIGURATION_FILE = "../task_config.json"

APKS_DIR = "../../apks/"

def main():
    # Set up the structure for configurations
    configs = {}
    for i in set(achtungs):
        configs[i] = {}
        configs[i] = defaultdict(list)

    if USE_SINA_FILTER:
        # Read sinas files and assign tasks to each achtung
        with open(SINA_FILTER) as inf:
            reader = csv.DictReader(inf)
            for line in reader:
                # Apparently True only marks high confidence ones, so disregard
                # this flag.
                # TODO: Rewrite this, doesn't really work with the new way we
                # use task_config
                if line["pinningFound"] == "True" or line["pinningFound"] == "False":
                    current_achtung = next(achtungpool)
                    apk_target_map = configs[current_achtung]["apk_target_map"]
                    app_hash = line["sha256"].upper()
                    # Convert the ';' seperated csv list, to a python list
                    pin_paths = line["pinPaths"][2:-2].split(";")
                    new_pin_paths = []
                    for pin_path in pin_paths:
                        # Save the class and ignore method for the time being
                        new_pin_paths.append(pin_path.split(".")[0])
                    apk_target_map[app_hash] = new_pin_paths

    else:
        # Just read the .apk files from the right dir, split them up to the right
        # achtung and leave the search path list blank.
        apks = get_apks(APKS_DIR)
        for apk_path in apks:
            current_achtung = next(achtungpool)
            # Save an empty list, drop path and .apk
            apk = apk_path.split('/')[-1]
            apk_name = apk[:-4].upper()
            # Writing string search config first
            # configs[current_achtung] \
            #    [task_variables.STRING_SEARCH_JOB].append(apk)
            # Write NSC job config
            configs[current_achtung][task_variables.NSC_JOB].append(apk)
            # Lastly write trust manager search job, this ones more complex, so
            # skipping for now

    task_counter = 0
    for achtung, jobs in configs.items():
        print("Machine:", achtung)
        for job, job_conf in jobs.items():
            print("     Job:", job, len(job_conf))
            task_counter += len(job_conf)
        print("===============================================================")
    print("Total tasks:", task_counter)
    with open(CONFIGURATION_FILE, "w") as ouf:
        json.dump(configs, fp=ouf, sort_keys=True, indent=2)

def get_apks(path):
    apks = []
    # Folders in the apks path
    for i in os.listdir(path):
        apk_file = os.path.join(path, i)
        if i.endswith(".apk"):
            apks.append(apk_file)
    return apks

# Boilerplate
if __name__ == "__main__":
    main()
