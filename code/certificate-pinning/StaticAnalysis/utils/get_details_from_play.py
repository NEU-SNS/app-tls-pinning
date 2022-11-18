#!/usr/bin/env python3
import play_scraper
import argparse
import sys
import os
import json

verbose = False

apk_ids = {}
app_details = {}
details_to_store = ['title', 'category', 'description', 'free', 'developer_id', 'updated', 'installs', 'current_version', 'required_android_version', 'developer', 'developer_url', 'app_id', 'url'] #add other play_store attributes that you want here
parser = argparse.ArgumentParser()

def info(package_name):
    ret = {}
    details = None
    try:
        details = play_scraper.details(package_name) #this is the key api that allows information retrieval from playstore
    except:
        print("couldn't retrive package details!")
    if details:
        for detail_name, detail_data in details.items():
            if detail_name in details_to_store:
                if verbose:
                    print(str(detail_data))
                ret[detail_name] = detail_data
    return ret

def main():
    parser.add_argument('--package-list', type=str, help='Package name list seperated by lines', default="")
    parser.add_argument('--output', type=str, help='Json to write the output to.', default="play_details.json")
    parser.add_argument('--verbose', action='store_true', help='Continue from where you left off', default=False)
    args = parser.parse_args()
    pack_lst_file = args.package_list
    out_json = args.output
    global verbose
    verbose = args.verbose
    pack_lst = []

    all_details = {}

    if pack_lst_file == "":
        print("Please supply package list file with --package-list")
        return
    try:
        with open(pack_lst_file, "r") as inf:
            for line in inf.readlines():
                pack_lst.append(line.strip())
    except Exception as e:
        print("Problem opening package list file", e)
        return

    for package_name in pack_lst:
        print("Looking up:", package_name)
        details = info(package_name)
        all_details[package_name] = details

    with open(out_json, "w") as ouf:
        json.dump(all_details, sort_keys=True, indent=2, fp=ouf)

if __name__ == "__main__":
    main()
