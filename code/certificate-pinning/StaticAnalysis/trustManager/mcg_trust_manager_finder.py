#!/usr/bin/env python3
import os
import json
import multiprocessing
from androguard.core.bytecode import FormatClassToJava
from androguard.misc import AnalyzeAPK
import networkx as nx
import csv
import argparse
import sys
import socket
import time
from collections import defaultdict

# This dir contains the set of .apks to process, no decompilation necessary.
APKS_DIR = "../../apks/"
CONFIGURATION_FILE = "../task_config.json"
RESULTS_DIR = "./mcg_results/"
RESULTS_EXTN = ".json"

CLASS_REGEX = [
    "Ljavax/net/ssl/SSLContext;"
]
ALL_REGEX = ".*"

def main():
    # Create necessary dirs
    create_dir(RESULTS_DIR)
    start = time.time()
    # Walk through all apk dirs, look for .xmls
    apks = get_apks()
    print("Processing:", len(apks))
    worker_pool = multiprocessing.Pool(min(40, multiprocessing.cpu_count()))
    res = worker_pool.map_async(process_apk, apks)
    total_tm_called = 0
    for i in res.get():
        total_tm_called += i
    print("Total Trust Manager calls found:", total_tm_called)
    worker_pool.close()
    worker_pool.join()
    print("Time taken:", time.time() - start, "seconds")

def create_dir(d):
    if not os.path.exists(d):
        os.makedirs(d)

def process_apk(apk_data):
    apk_file = apk_data[0]
    apk_pin_paths = apk_data[1]
    apk_name = apk_file.split("/")[-1]
    if apk_name.endswith(".apk"):
        apk_name = apk_name[:-4]
    print(apk_data)

    a, d, dx = AnalyzeAPK(apk_file)

    entry_points = list(map(FormatClassToJava,
                   a.get_activities() + a.get_providers() +
                   a.get_services() + a.get_receivers()))

    entry_methods = get_entry_methods(dx, entry_points)

    exit_map = defaultdict(set)
    # Build a call path and see if it matches a pin class
    for em in entry_methods:
        call_path = list(get_call_path(em))
        for pin_path in apk_pin_paths:
            # better bookkeeping could make this easier to find
            for cps in call_path:
                if pin_path in str(cps.get_class_name()):
                    exit_map[str(em.get_descriptor())].add(pin_path)
    # Make the exit map json serializable
    for k, v in exit_map.items():
        exit_map[k] = list(v)
    if len(exit_map) > 0:
        with open(RESULTS_DIR + apk_name + RESULTS_EXTN, "w") as ouf:
            json.dump(exit_map, fp=ouf, sort_keys=True, indent=4)
        return 1
    return 0

def get_call_path(method, methods_seen=set()):
    """
    Given a method, extracts all methods that would at some point be called, if
    this node is called. Thus, if a target lies in this path, it will be called
    at some execution of this node.
    """
    methods_seen.add(method)
    for m in method.get_xref_to():
        # Add this xrefs class name, and get recurse
        m = m[1] # Just get the method analysis
        if m in methods_seen:
            continue
        methods_seen.update(get_call_path(m, methods_seen))
    return methods_seen

def get_entry_methods(dx, entry_points):
    """
    Return a list of method analysis objects that are entry methods, using the
    entry_points list which contains all entry points for an apk.
    https://github.com/androguard/androguard/blob/cba2e87ae9240a0dbef5886bae5f0e6bf7541883/androguard/core/analysis/analysis.py#L1920
    """
    ret_lst = []
    # We use no regex at the moment
    for method in dx.find_methods():
        if method.class_name in entry_points:
            ret_lst.append(method)
    return ret_lst

# Relies heavily on filename format and filter format, must change in the future
def get_apks():
    machine_name = socket.gethostname()
    # Config file contains mappings for all machines, just need to get this machines
    with open(CONFIGURATION_FILE) as inf:
        configuration = json.load(inf)
        try:
            my_configuration = configuration[machine_name]
        except KeyError:
            print("No tasks for this machine...")
            return []
    # Our config has a APK hash to pin mapping, which we need to search for.
    apk_target_map = my_configuration["apk_target_map"]
    apks_to_process = list(apk_target_map.keys())
    apks = []
    # Search for the apk file in that dir, and make sure it belongs to the set we need to process
    for i in os.listdir(APKS_DIR):
        apk_file = os.path.join(APKS_DIR, i)
        app_hash = i[:-4].upper()
        if i.endswith(".apk") and app_hash in apks_to_process:
            apks.append((apk_file, apk_target_map[app_hash]))
    return apks

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

# Boilerplate
if __name__ == "__main__":
    main()
