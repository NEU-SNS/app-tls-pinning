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

MIXED_PINNING_OUTPUT = "pinning_not_pinning_by_party.pdf"

def check_and_load(infile, default=""):
    if infile != default:
        with open(infile, "r") as inf:
            return json.load(inf)
    return default

def main():
    parser = argparse.ArgumentParser(description='Create stacked bar chart to compare pinned/not-pinned 1st and 3rd party domains.')
    parser.add_argument('--json', help='pinning_attributed.json file with required keys.', type=str, nargs='?', default="")
    parser.add_argument('--details', help='Package to title mappings', type=str, nargs='?', default="")
    parser.add_argument('--common', help='Result for common 600', type=str, nargs='?', default="")
    parser.add_argument('--random', help='Result for random 1k', type=str, nargs='?', default="")
    parser.add_argument('--popular', help='Result for popular 1k', type=str, nargs='?', default="")
    args = parser.parse_args(sys.argv[1:])
    try:
        pinning_attributed = check_and_load(args.json)
        package_details = check_and_load(args.details)
        common = check_and_load(args.common)
        random = check_and_load(args.random)
        popular = check_and_load(args.popular)
    except Exception as e:
        print("Failed to open json file...", e)
        return

    space = pd.DataFrame({
        FPNP: {"blank1": 0, "blank2": 0},
        FPP: {"blank1": 0, "blank2": 0},
        TPNP: {"blank1": 0, "blank2": 0},
        TPP: {"blank1": 0, "blank2": 0}
    })

    # df_common = get_dataframe_from_pinning_result(common).append(space)
    df_random = get_dataframe_from_pinning_result(random)
    df_popular = get_dataframe_from_pinning_result(popular)
    # common_len = len(df_common)
    random_len = len(df_random)
    popular_len = len(df_popular)
    # Could add spacing between the appends to make distinctions clearer
    df_popular = df_popular.append(space)
    # df = df_common.append(df_random.append(df_popular))
    df = df_popular.append(df_random)
    first = popular_len + 0.5
    # second = common_len + random_len - 1.5
    print(df)
    colors = {
        FPNP: "#026C32",
        TPNP: "#5DE3BD",
        FPP:  "#02326C",
        TPP:  "#5DBDE3"
    }
    ax = df.plot.bar(stacked=True, color=colors)
    plt.setp(ax.get_xticklabels(), rotation=0)
    plt.setp(ax.get_yticklabels(), rotation=0)
    # plt.legend([FPP, FPNP, TPP, TPNP])
    plt.legend(loc='upper left', bbox_to_anchor=(0, 1.15), ncol=4)
    for i in [-100, -75, -50, -25, 0, 25, 50, 75, 100]:
        plt.axhline(i, color='white', ls="dotted")
    ax.set_yticklabels([0, 100, 75, 50, 25, 0, 25, 50, 75, 100])
    ax.set_xticks([int(popular_len/2), int(popular_len+(random_len/2))])
    ax.set_xticklabels(["Popular (" + str(popular_len) +")", "Random(" + str(random_len) +")"])
    ax.set_ylabel("% Domains contacted pinned(blue)\n and not pinned(green)")
    plt.axvline(x=first, lw=0.5)
    # plt.axvline(x=second, lw=0.5)
    plt.show()
    plt.savefig(MIXED_PINNING_OUTPUT, dpi=2000)

# Extract required data from play details json file
def get_play_titles(play_details):
    ret_details = {}
    for package_name, package_details in play_details.items():
        if 'title' in package_details:
            ret_details[play_details] = package_details['title']
    return ret_details

def get_dataframe_from_pinning_result(pinning_attributed, package_details={}):
    packages_seen = defaultdict(dict)
    for package_name, fpnp in pinning_attributed[FPNP].items():
        packages_seen[package_name][FPNP] = fpnp
    for package_name, fpp in pinning_attributed[FPP].items():
        packages_seen[package_name][FPP] = fpp
    for package_name, tpnp in pinning_attributed[TPNP].items():
        packages_seen[package_name][TPNP] = tpnp
    for package_name, tpp in pinning_attributed[TPP].items():
        packages_seen[package_name][TPP] = tpp
    print("Seen", len(packages_seen))
    pinning_typ_to_package_percentages = defaultdict(dict)
    pack_sorting = defaultdict(float)
    for package_name, pin_type_to_dom in packages_seen.items():
        # Convert package name to app name if possible
        if package_name in package_details:
            package_name = package_details[package_name]
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
    return pd.DataFrame(pinning_typ_to_package_percentages, index=pack_order)

if __name__ == "__main__":
    main()
