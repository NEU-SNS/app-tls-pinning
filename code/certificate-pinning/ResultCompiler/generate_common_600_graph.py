#!/usr/bin/env python3
import sys
from collections import defaultdict
import json
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Pinning attributed keys:
FPNP = "FIRST_PARTY_NOT_PINNED"
FPP  = "FIRST_PARTY_PINNED"
TPNP = "THIRD_PARTY_NOT_PINNED"
TPP  = "THIRD_PARTY_PINNED"

PAPI = "PIN_ANDROID_PIN_IOS"
PAUPI = "PIN_ANDROID_UNPIN_IOS"
UPAPI = "UNIPN_ANDROID_PIN_IOS"
UPAUPI = "UNPIN_ANDROID_UNPIN_IOS"
ALL_HOSTS_JACCARD = "ALL_HOSTS_JACCARD"

PINNING_SCORE = "PINNING_SCORE"
ANDROID_SCORE = 0.33
IOS_SCORE = 0.66
PINNING_BOTH = 1

"""
Android/iOS results:
    A results summary mapping
    {FPNP: {package_name: [domain1, ..., domainN]}, FPP: ....,}
Common map:
    {IPA_Name: {"ios_package": "ios_package_name", "android_package": "android_package_name"} ...}
Android/iOS domains:
    {android/ios_package_name: [domain1, ..., domainN]}
"""

def main():
    parser = argparse.ArgumentParser(description='Create chart to compare common 600 apps')
    parser.add_argument('--commonmap', help='Android-iOS package name mappings', type=str, nargs='?', required=True)
    parser.add_argument('--play', help='Play details json', type=str, nargs='?', required=True)
    parser.add_argument('--ios', help='Common 600 result_summary.json for iOS', type=str, nargs='?', required=True)
    parser.add_argument('--android', help='Common 600 result_summary.json for Android', type=str, nargs='?', required=True)
    parser.add_argument('--anddomains', help='Android domains for common 600', type=str, nargs='?', required=True)
    parser.add_argument('--iosdomains', help='iOS domains for common 600', type=str, nargs='?', required=True)
    args = parser.parse_args(sys.argv[1:])
    try:
        with open(args.commonmap, "r") as inf:
            common_map = json.load(inf)
        with open(args.ios, "r") as inf:
            ios_results = json.load(inf)
        with open(args.android, "r") as inf:
            android_results = json.load(inf)
        with open(args.play, "r") as inf:
            play_details = json.load(inf)
        with open(args.anddomains, "r") as inf:
            android_domains_contacted = json.load(inf)
        with open(args.iosdomains, "r") as inf:
            ios_domains_contacted = json.load(inf)
    except Exception as e:
        print("Failed to open json file...", e)
        return
    and_to_ios, ios_to_and, ios_to_ipa = get_double_mappings(common_map)
    print("Got package mappings:", len(and_to_ios))
    android_results = flip_results(android_results)
    ios_results = flip_results(ios_results)
    print("Android results:", len(android_results), "iOS results:", len(ios_results))
    jaccards = {}
    all_hosts = {}
    android_only = set()
    ios_only = set()
    both_pinning = set()
    for android_package_name in android_results.keys():
        ios_package_name = and_to_ios[android_package_name]
        android_result = android_results[android_package_name]
        try:
            android_domains = android_domains_contacted[android_package_name]
        except KeyError:
            print("No domains contacted for Android:", android_package_name)
            android_domains = []
        try:
            ios_domains = ios_domains_contacted[ios_package_name]
        except KeyError:
            print("No domains contacted for iOS:", ios_package_name)
            ios_domains = []
        # Assume no iOS result
        ios_result = {}
        pin_score = 0
        if ios_package_name in ios_results:
            both_pinning.add(android_package_name)
            print("Android result in iOS:", android_package_name)
            ios_result = ios_results[ios_package_name]
            pin_score = PINNING_BOTH
        else:
            android_only.add(android_package_name)
            print("Android only", android_package_name)
            pin_score = ANDROID_SCORE
            ios_result[FPNP] = ios_domains
        these_jaccards = get_all_set_jaccards(android_result, ios_result)
        these_jaccards[ALL_HOSTS_JACCARD] = set_jaccard(set(android_domains), set(ios_domains))
        these_jaccards[PINNING_SCORE] = pin_score
        jaccards[android_package_name] = these_jaccards

    for ios_package_name in ios_results.keys():
        android_package_name = ios_to_and[ios_package_name]
        try:
            android_domains = android_domains_contacted[android_package_name]
        except KeyError:
            print("No domains contacted for Android:", android_package_name)
            android_domains = []
        try:
            ios_domains = ios_domains_contacted[ios_package_name]
        except KeyError:
            print("No domains contacted for iOS:", ios_package_name)
            ios_domains = []
        if android_package_name not in jaccards:
            # Fill in jaccards with iOS exclusive values
            ios_only.add(android_package_name)
            print("iOS only", android_package_name)
            these_jaccards = get_all_set_jaccards({FPNP: android_domains}, ios_results[ios_package_name])
            these_jaccards[ALL_HOSTS_JACCARD] = set_jaccard(set(android_domains), set(ios_domains))
            these_jaccards[PINNING_SCORE] = IOS_SCORE
            jaccards[android_package_name] = these_jaccards

    print("Android Only:", len(android_only), "iOS only:", len(ios_only), "Both:", len(both_pinning))
    cdf_data = defaultdict(float)
    heatmap_data = defaultdict(list)
    ordered_app_names = []
    some_ordered_items = [(k, v) for k, v in sorted(jaccards.items(), key=lambda x: (x[1][PAPI]*10000 + x[1][PAUPI]*100 + x[1][UPAPI]), reverse=True)]
    # Different combinations here generate different rows in the heatmap.
    for pack, jaccard in some_ordered_items:
        # if not is_ios_only_inconsistent_row(pack, jaccard, and_to_ios):
        #     continue
        # if not is_android_only_inconsistent_row(pack, jaccard, and_to_ios):
        #    continue
        if not is_both_inconsistent_row(pack, jaccard, and_to_ios):
            continue
        cdf_data[round(jaccard[ALL_HOSTS_JACCARD], 2)] += 1
        app_name = get_play_title(pack, play_details)
        ordered_app_names.append(app_name)
        for overlap_name, overlap_value in jaccard.items():
            heatmap_data[overlap_name].append(overlap_value)

    # Modify this based on which of the overlap columns are necessary
    # Order the heatmap_data
    heatmap_column_order = [
        # ALL_HOSTS_JACCARD,
        PAPI, # both column
        # UPAUPI,
        PAUPI, # and only column and both
        UPAPI, # ios only column and both
        # PINNING_SCORE
    ]
    print("This set pinning:", len(heatmap_data[ALL_HOSTS_JACCARD]))
    ctr = 0
    for val in heatmap_data[PAPI]:
        if val == 1:
            ctr += 1
    print("Some counter:", ctr, "check code to see what this is.")
    heatmap_column_name = {
        ALL_HOSTS_JACCARD: "Jaccard \n(all domains)",
        PAPI: "Pinned Android &\n Pinned iOS",
        UPAUPI: "Not Pinned\n(either)",
        PAUPI: "% of Pinned Android \n Not Pinned on iOS",
        UPAPI: "% of Pinned iOS \n Not Pinned on Android",
        PINNING_SCORE: "Pinning platform"
    }
    ordered_heatmap_data = {heatmap_column_name[k] : heatmap_data[k] for k in heatmap_column_order}
    df = pd.DataFrame(ordered_heatmap_data, index=ordered_app_names)
    plt.rcParams['pdf.fonttype'] = 42
    plt.rcParams['ps.fonttype'] = 42
    ax = sns.heatmap(df, annot=True, fmt='.3g', cmap='YlGnBu', yticklabels=True, cbar=False)

    # Rewrite to percentages
    for label in ax.texts:
        #if label._x != 0.5:
        label.set_text(str(round(float(label.get_text())*100))+"%")

    plt.setp(ax.get_xticklabels(), rotation=15)
    plt.setp(ax.get_yticklabels(), rotation=0)
    # plt.rcParams['text.usetex'] = True
    #plt.rcParams.update({
    #"pdf.use14corefonts": True
    #})
    # plt.show()
    fig = plt.gcf()
    fig.set_size_inches(5, 5)
    for label in fig.texts:
        label.set_text(str(float(label.get_text())*100)+"%")
    fig.savefig('common_heatmap.pdf', dpi=150, bbox_inches='tight')
    # plt.show()
    # In case you want to CDF the jaccard scores
    # write_CDF(cdf_data, "test.pdf", "CDF of jaccards for apps seen with pinning.")

MANUAL_TITLES = {
    "com.jicabs": "jiCabs",
    "com.snpx.customer": "Senpex"
}

def is_ios_only_inconsistent_row(pack, jaccard, and_to_ios):
    # == 1 is hacky to deal with 1 case that wasn't seen in rerun
    # If clean, similar to android should be > 0
    if jaccard[PINNING_SCORE] == IOS_SCORE and \
            jaccard[UPAPI] == 1:
        print("iiOS:", pack, and_to_ios[pack])
        return True
    return False

def is_android_only_inconsistent_row(pack, jaccard, and_to_ios):
    if jaccard[PINNING_SCORE] == ANDROID_SCORE and \
            jaccard[PAUPI] > 0:
        print("Andr:", pack, and_to_ios[pack])
        return True
    return False

def is_both_inconsistent_row(pack, jaccard, and_to_ios):
    # No inconsistency, as there is no overlap between pinning on one and
    # not pinned on other for either platform
    if jaccard[PAUPI] == 0 and jaccard[UPAPI] == 0:
        return False
    # Chegg hack, cleaned data doesn't have this
    elif jaccard[PAUPI] == 1 and jaccard[UPAPI] == 1:
        return False
    elif jaccard[PINNING_SCORE] == PINNING_BOTH:
        return True
    return False

def get_play_title(package_name, play_details):
    if package_name in play_details and 'title' in play_details[package_name]:
        return play_details[package_name]['title'].split(' ')[0].split(":")[0]
    else:
        return MANUAL_TITLES[package_name]
    return package_name

def get_all_set_jaccards(android_result, ios_result):
    and_pinned = set()
    ios_pinned = set()
    and_unpin = set()
    ios_unpin = set()
    result_to_set = [
        (FPP, and_pinned),
        (TPP, and_pinned),
        (FPNP, and_unpin),
        (TPNP, and_unpin)
    ]
    for result, set_to_update in result_to_set:
        if result in android_result:
            set_to_update.update(android_result[result])
    result_to_set = [
        (FPP, ios_pinned),
        (TPP, ios_pinned),
        (FPNP, ios_unpin),
        (TPNP, ios_unpin)
    ]
    for result, set_to_update in result_to_set:
        if result in ios_result:
            set_to_update.update(ios_result[result])
    and_all = and_pinned.union(and_unpin)
    ios_all = ios_pinned.union(ios_unpin)
    all_all = and_all.union(ios_all)
    print("A Hosts:", len(all_all))
    print("AND extra:", sorted(and_all-ios_all))
    print("IOS extra:", sorted(ios_all-and_all))
    print("Common:", sorted(all_all))
    return {
        PAPI: set_jaccard(and_pinned, ios_pinned),
        PAUPI: pinned_unpinned(and_pinned, ios_unpin),
        UPAPI: pinned_unpinned(ios_pinned, and_unpin),
        UPAUPI: set_jaccard(and_unpin, ios_unpin)
    }
    # Moving all hosts jaccard calculation from here, will calculate in the calling function
    # using info from and_hosts_contacted and ios_hosts_contacted
        #ALL_HOSTS_JACCARD: set_jaccard(and_all, ios_all)

def set_jaccard(s1, s2):
    if len(s1) == 0 and len(s2) == 0:
        print("nulls")
        return 0
    return round(len(s1.intersection(s2)) / len(s1.union(s2)), 2)

def pinned_unpinned(pinned, unpinned):
    if len(pinned) == 0 or len(unpinned) == 0:
        return 0
    return round(len(pinned.intersection(unpinned)) / len(pinned), 2)

def flip_results(some_results):
    ret_results = defaultdict(dict)
    for package_name, fpnp in some_results[FPNP].items():
        ret_results[package_name][FPNP] = fpnp
    for package_name, fpp in some_results[FPP].items():
        ret_results[package_name][FPP] = fpp
    for package_name, tpnp in some_results[TPNP].items():
        ret_results[package_name][TPNP] = tpnp
    for package_name, tpp in some_results[TPP].items():
        ret_results[package_name][TPP] = tpp
    return ret_results

def get_double_mappings(common_map):
    and_to_ios = {}
    ios_to_and = {}
    ios_to_ipa = {}
    for ipa_name, package_names in common_map.items():
        and_pack = package_names["android_package"]
        ios_pack = package_names["ios_package"]
        and_to_ios[and_pack] = ios_pack
        ios_to_and[ios_pack] = and_pack
        ios_to_ipa[ios_pack] = ipa_name
    return and_to_ios, ios_to_and, ios_to_ipa

def plot_setup():
    plt.rcParams['axes.labelsize'] = '7'
    plt.rcParams['axes.titlesize'] = '7'
    plt.rcParams['lines.linewidth'] = '1'
    plt.rcParams['xtick.labelsize'] = '7'
    plt.rcParams['ytick.labelsize'] = '7'
    plt.rcParams['grid.color'] = 'gray'
    plt.rcParams['grid.linestyle'] = ':'
    plt.rcParams['grid.linewidth'] = 0.75
    plt.rcParams['patch.force_edgecolor'] = True
    plt.rcParams['patch.facecolor'] = 'b'
    # plt.rcParams['xtick.direction'] = 'in'
    # plt.rcParams['ytick.direction'] = 'in'
    plt.rcParams['xtick.major.size'] = '3'
    plt.rcParams['ytick.major.size'] = '3'
    plt.rcParams['xtick.major.width'] = '0.5'
    plt.rcParams['ytick.major.width'] = '0.5'
    fig = plt.figure(figsize=(3.12561, 1.6))
    fig.set_tight_layout({"pad": 0, "rect": [0, 0, 1, 1]})
    ax = fig.add_subplot(111)
    # Plot stuff
    plt.tight_layout()

def write_CDF(cdf_data, out_file, xlabel="Default x label."):
    cdf_total = 0
    print("CDF data:", cdf_data)
    for k, v in cdf_data.items():
        cdf_total += v
    moving_sum = 0
    cdf_x = [0]
    cdf_y = [0]
    for i in sorted(cdf_data.keys()):
        moving_sum += cdf_data[i]
        cdf_x.append(i) # We have the x axis to plot.
        cdf_y.append(moving_sum / cdf_total) # We have the y axis point.
    plot_setup()
    plt.step(cdf_x, cdf_y)
    plt.grid(linestyle=":")
    plt.xticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    plt.xlim(left=-0.1, right=1)
    plt.ylim(bottom=0.0, top=1.1)
    plt.ylabel("CDF")
    plt.xlabel(xlabel)
    plt.savefig(out_file, dpi=2000)
    plt.close()
    # print("CDF(x, y)", cdf_x, cdf_y)
    print("Total CDF data:", cdf_total)

if __name__ == "__main__":
    main()
