#!/usr/bin/env python3
import sys
from collections import defaultdict
import json
import argparse
import pandas as pd
import matplotlib.pyplot as plt

# Pinning attributed keys:
FPNP = "FIRST_PARTY_NOT_PINNED"
FPP  = "FIRST_PARTY_PINNED"
TPNP = "THIRD_PARTY_NOT_PINNED"
TPP  = "THIRD_PARTY_PINNED"

PINNING_KEY = "failed_handshakes"
NOT_PINNING_KEY = "successful_handshakes"

THIRD_PARTY_PINNED_NOT_PINNED = "3rd_party_pinned_not_pinned.pdf"


def main():
    parser = argparse.ArgumentParser(description='Create stacked bar chart to compare pinned/not-pinned 3rd party domains by packages theyre found in.')
    parser.add_argument('--results', help='pinning_attributed.json file with required keys.', type=str, nargs='?', required=True)
    parser.add_argument('--firstparty', help='', type=str, nargs='?', required=True)
    args = parser.parse_args(sys.argv[1:])
    try:
        with open(args.results, "r") as inf:
            result_summary = json.load(inf)
        with open(args.firstparty, "r") as inf:
            first_party_map = json.load(inf)
    except:
        print("Failed to open some json file...")

    third_to_pinned, third_to_not_pinned = \
        get_third_parties_pinning(result_summary, first_party_map)

    print("Third parties that pin:", len(third_to_pinned), \
        "don't pin:", len(third_to_not_pinned))

    third_pinned_percentage = defaultdict(dict)
    for third_party, pinned_apps in third_to_pinned.items():
        not_pinned_apps = set()
        save = True
        if third_party in third_to_not_pinned:
            save = True
            not_pinned_apps = third_to_not_pinned[third_party]
        if not save:
            continue
        total_apps = len(pinned_apps.union(not_pinned_apps))
        third_pinned_percentage[third_party]["PINNED"] = pinned_apps
            # (100.0 * len(pinned_apps)) / total_apps
        third_pinned_percentage[third_party]["NOT_PINNED"] = not_pinned_apps
            # (100.0 * len(not_pinned_apps)) / total_apps
    df = pd.DataFrame(third_pinned_percentage, index=["PINNED", "NOT_PINNED"])
    for p in sorted(third_pinned_percentage.items(), key=lambda x: len(x[1]["PINNED"])*-1):
        if len(p[1]["PINNED"]) > 1:
            print(p[0], p[1]["PINNED"], len(p[1]["NOT_PINNED"]))
    plt.show()
    return

    for package_name, pin_type_to_dom in packages_seen.items():
        # Convert package name to app name if possible
        if package_name in play_details and 'title' in play_details[package_name]:
            package_name = play_details[package_name]['title'].split(":")[0]
            package_name = package_name.split(" ")[0]
        domains_contacted = set()
        for type_of_pinning, domains in pin_type_to_dom.items():
            domains_contacted.update(domains)
        for type_of_pinning in [FPNP, TPNP, FPP, TPP]:
            save = 0
            if type_of_pinning in pin_type_to_dom:
                domains = pin_type_to_dom[type_of_pinning]
                save = round((len(domains) * 100.0) / len(domains_contacted), 2)
            if type_of_pinning in [FPNP, TPNP]:
                save = save*-1
            else:
                pack_sorting[package_name] += save
            pinning_typ_to_package_percentages[type_of_pinning][package_name] = save
    pack_sorting = sorted(pack_sorting.items(), key=lambda d: d[1])
    pack_order = []
    for p in pack_sorting:
        pack_order.append(p[0])
    df = pd.DataFrame(pinning_typ_to_package_percentages, index=pack_order)
    print(df)
    colors = {
        FPNP: "#026C32",
        TPNP: "#5DE3BD",
        FPP:  "#02326C",
        TPP:  "#5DBDE3"
    }
    ax = df.plot.barh(stacked=True, color=colors)
    plt.setp(ax.get_xticklabels(), rotation=0)
    plt.setp(ax.get_yticklabels(), rotation=0)
    for i in [-100, -75, -50, -25, 0, 25, 50, 75, 100]:
        plt.axvline(i, color='white', ls="dotted")
    ax.set_xticklabels([100, 75, 50, 25, 0, 25, 50, 75, 100])
    # plt.show()
    plt.savefig(THIRD_PARTY_PINNED_NOT_PINNED, dpi=2000)

def get_third_parties_pinning(result_summary, first_party_map):
    third_to_pinned_apps = defaultdict(set)
    third_to_not_pinned_apps = defaultdict(set)
    for package_hash, pin_status_dict in result_summary.items():
        if PINNING_KEY in pin_status_dict:
            for ip, domains in pin_status_dict[PINNING_KEY].items():
                for domain in domains:
                    # domain = ".".join(domain.split(".")[-2:])
                    first_party = package_hash in first_party_map and \
                        domain in first_party_map[package_hash]
                    if not first_party:
                        third_to_pinned_apps[domain].add(package_hash)
        elif NOT_PINNING_KEY in pin_status_dict:
            for ip, domains in pin_status_dict[NOT_PINNING_KEY].items():
                for domain in domains:
                    # domain = ".".join(domain.split(".")[-2:])
                    first_party = package_hash in first_party_map and \
                        domain in first_party_map[package_hash]
                    if not first_party:
                        third_to_not_pinned_apps[domain].add(package_hash)
    return third_to_pinned_apps, third_to_not_pinned_apps

if __name__ == "__main__":
    main()
