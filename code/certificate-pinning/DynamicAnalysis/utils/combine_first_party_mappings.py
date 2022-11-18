#!/usr/bin/env python3
import os
import sys
import json
from collections import defaultdict

COMBINED_FIRST_PARTY_MAP = "combined_first_party_map.json"


"""
Script to combine two first_party_map.json files together, merging the domains
that are in the files.

first_party_map.json format:
{
"pack_name": ["list", "of", "domains"]
}

Basically used to easily update mappings from first_party_missed.json files
generated from the compile_tls_hangup_results.py script.
"""

def main():
    # Walk through all apk dirs, look for .xmls
    if len(sys.argv) < 3:
        print("Please provide at least 2 .json file to combine.")
        return
    else:
        first_party_map_jsons = sys.argv[1:]
    final_mappings = defaultdict(set)
    for this_mapping in first_party_map_jsons:
        try:
            with open(this_mapping, "r") as inf:
                a_mapping = json.load(inf)
        except:
            print("Error opening a mapping:", this_mapping)
            continue
        for package_name, first_parties in a_mapping.items():
            final_mappings[package_name].update(first_parties)
    with open(COMBINED_FIRST_PARTY_MAP, "w") as ouf:
        json.dump(final_mappings, fp=ouf, sort_keys=True, indent=2, default=serialize_sets)

def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj

# Boilerplate
if __name__ == "__main__":
    main()
