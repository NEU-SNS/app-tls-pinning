#!/usr/bin/env python3
import os
import sys
import subprocess
import multiprocessing
import json
from androguard.misc import AnalyzeAPK

def get_files_with_ending(path, ending):
    files_found = []
    for i, _, v in os.walk(path):
        for j in v:
            if j.endswith(ending):
                files_found.append(i + "/" + j)
    return files_found

def main():
    # Walk through all apk dirs, look for .xmls
    apks = get_files_with_ending(".", ".apk")
    worker_pool = multiprocessing.Pool()
    res = worker_pool.map_async(get_classes, apks)
    d = 0
    for i in res.get():
        d += i
    print("Total APKs decompiled:", d)
    worker_pool.close()
    worker_pool.join()

def get_classes(apk_file):
    apk_hash = apk_file[:-4]
    a, d, dx = AnalyzeAPK(apk_file)
    with open("./classes/" + apk_hash + ".json", "w") as ouf:
        res = set()
        for i in dx.get_classes():
            class_name = str(i.name)
            if class_name.startswith("L"):
                class_name = class_name[1:]
            class_name = class_name.replace("/", ".")
            res.add(class_name) # Save just class names for now
        res = list(res)
        json.dump(res, fp=ouf, sort_keys=True, indent=4)
        return 1
    return 0

def decompile_apk(apk_file):
    result = subprocess.call(['apktool', 'd', apk_file])
    if result == 0:
        return 1
    else:
        return 0

# Boilerplate
if __name__ == "__main__":
    main()
