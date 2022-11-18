#!/usr/bin/env python3
import os
import sys
import json
from collections import defaultdict
import argparse
import glob

# Pinning attributed keys:
FPNP = "FIRST_PARTY_NOT_PINNED"
FPP  = "FIRST_PARTY_PINNED"
TPNP = "THIRD_PARTY_NOT_PINNED"
TPP  = "THIRD_PARTY_PINNED"

CIPHERS_EXTN = ".cipher"

WEAK = "weak_cipher"
PROB = "problem_cipher"

BAD_TLS_AND_PINNING = "bad_tls_and_pinning.json"

def main():
    parser = argparse.ArgumentParser(description='Detect cipher problems if any.')
    parser.add_argument('--results', help='Result summary json file', type=str, nargs='?', required=True)
    parser.add_argument('--ciphers', help='Folder where *.cipher files are', type=str, nargs='?', required=True)
    args = parser.parse_args(sys.argv[1:])
    with open(args.results, "r") as inf:
        results = json.load(inf)
    pinners = combine_pinned_domains(results[FPP], results[TPP])
    results = defaultdict(dict)
    mixed_security = set()
    bad_cipher_apps = set()
    bad_cipher_not_pinned = []
    bad_cipher_pinned = []
    for cipher_file in glob.glob(args.ciphers + "/*" + CIPHERS_EXTN):
        app_name = cipher_file.rsplit("/", 1)[1].rsplit("-", 1)[0]
        bad_cipher_apps.add(app_name)
        if app_name in pinners:
            mixed_security.add(app_name)
            print("#######################################")
            print(app_name)
            bad = set()
            with open(cipher_file, "r") as inf:
                cipher = json.load(inf)
            if WEAK in cipher:
                weak = set(cipher[WEAK])
                overlap = weak.intersection(pinners[app_name])
                bad.update(overlap)
                if len(overlap) > 0:
                    print("Weak found:", overlap)
                    results[app_name]["weak_and_pinned"] = overlap
            if PROB in cipher:
                prob = set(cipher)
                overlap = prob.intersection(pinners[app_name])
                bad.update(overlap)
                if len(overlap) > 0:
                    print("Problem found:", overlap)
                    results[app_name]["problem_and_pinned"] = overlap
            bad_cipher_pinned += list(bad)
            print("#######################################")
        else:
            bad = set()
            if WEAK in cipher:
                bad.update(cipher[WEAK])
            if PROB in cipher:
                bad.update(cipher[PROB])
            bad_cipher_not_pinned += list(bad)
    print("Mixed security apps:", len(mixed_security))#, mixed_security)
    print("Pinning with bad ciphers:", len(results))#, results.keys())
    print("Total pinned apps in this set:", len(pinners))
    print("All apps with bad ciphers:", len(bad_cipher_apps))
    print("weak overall", len(bad_cipher_not_pinned))
    print("weak pinned", len(bad_cipher_pinned))
    with open(BAD_TLS_AND_PINNING, "w") as ouf:
        json.dump(results, fp=ouf, sort_keys=True, indent=2, default=serialize_sets)

def combine_pinned_domains(r1, r2):
    rret = defaultdict(set)
    for k, v in r1.items():
        for dom in v:
            # Convert to cipher_check.py IP format
            if "without-SNI:" in dom:
                dom = "IP:" + dom.rsplit(" ", 1)[1]
            rret[k].add(dom)
    for k, v in r2.items():
        for dom in v:
            if "without-SNI:" in dom:
                dom = "IP:" + dom.rsplit(" ", 1)[1]
            rret[k].add(dom)
    return rret

def serialize_sets(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj

# Boilerplate
if __name__ == "__main__":
    main()
