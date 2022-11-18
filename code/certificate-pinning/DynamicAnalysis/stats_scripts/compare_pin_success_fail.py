#!/usr/bin/env python3
import json
import sys
import argparse
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(description='Compare pinning found hosts to no pinning hosts from 2 result summaries.')
    parser.add_argument('--fail', help='Compare failed_handshakes from this file', type=str, nargs='?', default="")
    parser.add_argument('--success', help='Compare successful_handshakes from this file', type=str, nargs='?', default="")
    args = parser.parse_args(sys.argv[1:])
    pass_stat = None
    fail_stat = None
    try:
        with open(args.success, "r") as inf:
            pass_stat = json.load(inf)
        with open(args.fail, "r") as inf:
            fail_stat = json.load(inf)
    except:
        print("Failed to open one of the files...")
    if pass_stat == None or fail_stat == None:
        print("Please supply valid success and fail stats")

    fail_stat_passing = defaultdict(set)
    fail_stat_failing = defaultdict(set)
    pass_stat_passing = defaultdict(set)
    pass_stat_failing = defaultdict(set)
    fail_to_pass = {}
    fail_to_fail = {}
    for pack_hash, pass_fail_dict in pass_stat.items():
        if "successful_handshakes" in pass_fail_dict:
            for ip, domains in pass_fail_dict["successful_handshakes"].items():
                pass_stat_passing[pack_hash].update(domains)
        if "failed_handshakes" in pass_fail_dict:
            for ip, domains in pass_fail_dict["failed_handshakes"].items():
                pass_stat_failing[pack_hash].update(domains)
    for pack_hash, pass_fail_dict in fail_stat.items():
        for ip, domains in pass_fail_dict["failed_handshakes"].items():
            fail_stat_failing[pack_hash].update(domains)
        if "successful_handshakes" in pass_fail_dict:
            for ip, domains in pass_fail_dict["successful_handshakes"].items():
                fail_stat_passing[pack_hash].update(domains)

    for pack_hash, failing in fail_stat_failing.items():
        # Failing is fail stats failing
        fail_to_pass_tmp = failing.intersection(pass_stat_passing[pack_hash])
        fail_to_fail_tmp = failing.intersection(pass_stat_failing[pack_hash])
        if len(fail_to_pass_tmp) > 0:
            fail_to_pass[pack_hash] = list(fail_to_pass_tmp)
        if len(fail_to_fail_tmp) > 0:
            fail_to_fail[pack_hash] = list(fail_to_fail_tmp)
    print("Successful circumvention:", len(fail_to_pass))
    for i, j in fail_to_pass.items():
        print(i, j)
    print("Remains failing:", len(fail_to_fail))
    for i, j in fail_to_fail.items():
        print(i, j)

if __name__ == "__main__":
    main()
