#!/usr/bin/env python3
import json
import sys
import argparse
from collections import defaultdict

COMPILED_RESULTS = "./compiled_results/"
PINNING_ATTRIBUTED = COMPILED_RESULTS + "pinning_attributed.json"
DOMAINS_CONTACTED = COMPILED_RESULTS + "domains_contacted.json"

THIRD_PARTIES = "./third_parties.json"

# Pinning attributed keys:
FPNP = "FIRST_PARTY_NOT_PINNED"
FPP  = "FIRST_PARTY_PINNED"
TPNP = "THIRD_PARTY_NOT_PINNED"
TPP  = "THIRD_PARTY_PINNED"

PACKAGE_FIRST_PARTY_MAP = "./stats_scripts/first_party_map.json"
KNOWN_THIRD_PARTY_ENDS = "./stats_scripts/known_third_party_ends.json"

def main():
    parser = argparse.ArgumentParser(description='Detect pinning based on 2 result summaries.')
    parser.add_argument('--mitm', help='MITMed result, base result to use.', type=str, nargs='?', default="")
    parser.add_argument('--nonmitm', help='Non mitm result, clean mitm result with this.', type=str, nargs='?', default="")
    args = parser.parse_args(sys.argv[1:])
    mitm_stat = None
    non_mitm_stat = None
    try:
        with open(args.mitm, "r") as inf:
            mitm_stat = json.load(inf)
        with open(args.nonmitm, "r") as inf:
            non_mitm_stat = json.load(inf)
    except:
        print("Failed to open one of the files...")
    if mitm_stat == None or non_mitm_stat == None:
        print("Please supply valid success and fail stats")

    mitm_stat_passing = defaultdict(set)
    mitm_stat_failing = defaultdict(set)
    non_mitm_stat_passing = defaultdict(set)
    non_mitm_stat_failing = defaultdict(set)

    # Load compiled result
    for pack_hash, pass_fail_dict in mitm_stat.items():
        if "successful_handshakes" in pass_fail_dict:
            for ip, domains in pass_fail_dict["successful_handshakes"].items():
                mitm_stat_passing[pack_hash].update(domains)
        if "failed_handshakes" in pass_fail_dict:
            for ip, domains in pass_fail_dict["failed_handshakes"].items():
                mitm_stat_failing[pack_hash].update(domains)
    for pack_hash, pass_fail_dict in non_mitm_stat.items():
        if "failed_handshakes" in pass_fail_dict:
            for ip, domains in pass_fail_dict["failed_handshakes"].items():
                non_mitm_stat_failing[pack_hash].update(domains)
        if "successful_handshakes" in pass_fail_dict:
            for ip, domains in pass_fail_dict["successful_handshakes"].items():
                non_mitm_stat_passing[pack_hash].update(domains)

    # IF mitm stat is failing but non mitm is passing, it is pinning
    pinning_found = {}
    # IF mitm stat is failing but non mitm is also failing, bad connection?
    always_failing = {}
    # IF mitm stat is passing and non mitm is failing, what is going on o.O
    mitm_only_passing = {}
    # IF mitm stat is passing and non mitm is passing, no pinning
    always_passing = {} # No pinning
    for pack_hash, fail_mitm in mitm_stat_failing.items():
        fail_mitm_pass_nonmitm = fail_mitm.intersection(non_mitm_stat_passing[pack_hash])
        fail_mitm_fail_nonmitm = fail_mitm.intersection(non_mitm_stat_failing[pack_hash])
        if len(fail_mitm_pass_nonmitm) > 0:
            pinning_found[pack_hash] = list(fail_mitm_pass_nonmitm)
        if len(fail_mitm_fail_nonmitm) > 0:
            always_failing[pack_hash] = list(fail_mitm_fail_nonmitm)
    for pack_hash, pass_mitm in mitm_stat_passing.items():
        pass_mitm_fail_nonmitm = pass_mitm.intersection(non_mitm_stat_failing[pack_hash])
        pass_mitm_pass_nonmitm = pass_mitm.intersection(non_mitm_stat_passing[pack_hash])
        if len(pass_mitm_fail_nonmitm) > 0:
            mitm_only_passing[pack_hash] = list(pass_mitm_fail_nonmitm)
        if len(pass_mitm_pass_nonmitm) > 0:
            always_passing[pack_hash] = list(pass_mitm_pass_nonmitm)
    print("########################################################")
    print("Pinning found:", len(pinning_found))
    print("########################################################")
    print("Always failing:", len(always_failing))
    for i, j in always_failing.items():
        print(i, j)
    print("########################################################")
    print("Pass mitm fail nonmitm:", len(mitm_only_passing))
    for i, j in mitm_only_passing.items():
        print(i, j)
    print("########################################################")
    print("Always passing:", len(always_passing))
    domains_contacted = {}
    # Writing always passing as domains contacted for now, check if you want to use something else here
    for pack_name_hash, domains in always_passing.items():
        pack_name, pack_hash = pack_name_hash.rsplit("-", 1)
        domains_contacted[pack_name] = domains
    for pack_name_hash, pinning_domains in pinning_found.items():
        pack_name, pack_hash = pack_name_hash.rsplit("-", 1)
        if pack_name in domains_contacted:
            domains_contacted[pack_name] = set(domains_contacted[pack_name]+pinning_domains)
        else:
            domains_contacted[pack_name] = pinning_domains
    with open(DOMAINS_CONTACTED, "w") as ouf:
        json.dump(domains_contacted, fp=ouf, sort_keys=True, indent=2, default=serialize_sets)
    print("########################################################")
    write_pinning_attributed(pinning_found, always_passing)

# Splitting pinned and not pinned connections into 1st and 3rd parties
# Helps plotting later (pinning_attributed.json)
# We've stopped handling package name collisions, rethink later how this
# affects combined results
def write_pinning_attributed(pinning_found, always_passing):
    with open(PACKAGE_FIRST_PARTY_MAP) as inf:
        pack_first_parties = json.load(inf)
    with open(KNOWN_THIRD_PARTY_ENDS) as inf:
        known_tp_ends = json.load(inf)
    first_party_pinned_map = defaultdict(set)
    first_party_not_pinned_map = defaultdict(set)
    third_party_pinned_map = defaultdict(set)
    third_party_not_pinned_map = defaultdict(set)
    third_parties = defaultdict(set)
    for pack_name_hash, pinned in pinning_found.items():
        pack_name, pack_hash = pack_name_hash.rsplit("-", 1)
        for d in pinned:
            if pack_name in pack_first_parties and d in pack_first_parties[pack_name]:
                first_party_pinned_map[pack_name].add(d)
            else:
                third_party_pinned_map[pack_name].add(d)
                third_parties[pack_name].add(d)
        if pack_name_hash in always_passing:
            not_pinned = always_passing[pack_name_hash]
            for d in not_pinned:
                if pack_name in pack_first_parties and d in pack_first_parties[pack_name]:
                    first_party_not_pinned_map[pack_name].add(d)
                else:
                    third_party_not_pinned_map[pack_name].add(d)
                    # third_parties[pack_name].add(d)
        print(pack_name, pinned)
    print("First party pinned:", len(first_party_pinned_map), \
            "Third party:", len(third_party_pinned_map), \
            "First party missed:", len(first_party_not_pinned_map), \
            "Third party missed:", len(third_party_not_pinned_map))
    with open(PINNING_ATTRIBUTED, "w") as ouf:
        json.dump({
            FPP: first_party_pinned_map,
            TPP: third_party_pinned_map,
            FPNP: first_party_not_pinned_map,
            TPNP: third_party_not_pinned_map
        }, fp=ouf, sort_keys=True, indent=2, default=serialize_sets)
    with open(THIRD_PARTIES, "w") as ouf:
        third_parties = remove_known_tp(third_parties, known_tp_ends)
        json.dump(third_parties, fp=ouf, sort_keys=True, indent=2, default=serialize_sets)

def remove_known_tp(third_parties, known_tp_ends):
    ret_tp = {}
    for key, values in third_parties.items():
        tmp = []
        for domain in values:
            add = True
            # Check ends for now, we can do full domains later
            for tp in known_tp_ends:
                if domain.endswith(tp):
                    add = False
            if add:
                tmp.append(domain)
        if len(tmp) > 0:
            ret_tp[key] = tmp
    return ret_tp


def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj

if __name__ == "__main__":
    main()
