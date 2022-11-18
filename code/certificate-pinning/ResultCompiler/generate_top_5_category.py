#!/usr/bin/env python3
import sys
from collections import defaultdict
import json
import argparse
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Pinning attributed keys:
FPNP = "FIRST_PARTY_NOT_PINNED"
FPP  = "FIRST_PARTY_PINNED"
TPNP = "THIRD_PARTY_NOT_PINNED"
TPP  = "THIRD_PARTY_PINNED"

TOP_5_HEATMAP = "top_5_heatmap.pdf"

CATEGORY_RANKS = "category_ranks.json"

def main():
    parser = argparse.ArgumentParser(description='Create heatmap for top 5 categories that pin')
    parser.add_argument('--details', help='Package to title mappings', type=str, nargs='?', default="")
    parser.add_argument('--common', help='Result for common 600', type=str, nargs='?', default="")
    parser.add_argument('--random', help='Result for random 1k', type=str, nargs='?', default="")
    parser.add_argument('--popular', help='Result for popular 1k', type=str, nargs='?', default="")
    parser.add_argument('--packs', help='Filter the packages by this text filter', type=str, nargs='?', default=None)
    args = parser.parse_args(sys.argv[1:])
    try:
        package_details = check_and_load(args.details)
        common = check_and_load(args.common)
        random = check_and_load(args.random)
        popular = check_and_load(args.popular)
        pack_filter = get_package_from_text(args.packs)
    except Exception as e:
        print("Failed to open json file...", e)
        return
    pinned_common = set(common[FPP]).union(set(common[TPP]))
    pinned_random = set(random[FPP]).union(set(random[TPP]))
    pinned_popular = set(popular[FPP]).union(set(popular[TPP]))
    print("Common:", len(pinned_common))
    print("Random:", len(pinned_random))
    print("Popular:", len(pinned_popular))
    all_pinners = pinned_common.union(pinned_random).union(pinned_popular)
    print("Total:", len(all_pinners))
    pinning_counts = get_category_by_popularity(all_pinners, package_details)
    dataset_category_counts_sorted, dataset_category_counts = get_category_counts(package_details)
    package_category_counts = get_category_counts_for_packages(pack_filter, package_details)
    print("Packages:", len(pack_filter))
    print("Only priting categories for now, edit to get overall category results")
    with open(CATEGORY_RANKS, "w") as ouf:
        json.dump(package_category_counts, fp=ouf, indent=2,)
    apps_seen = 0
    for k,v in package_category_counts.items():
        apps_seen += v
    print("Apps seen:", apps_seen)
    return

    category_ranks = [k for k, v in dataset_category_counts_sorted]
    normalized_category_counts = {}
    for category, pinning_count in pinning_counts.items():
        normalized = round(pinning_count*100/dataset_category_counts[category], 2)
        normalized_category_counts[category] = normalized
    sorted_normalized_category_counts = [(k,v) for k,v in sorted(normalized_category_counts.items(), key=lambda x: x[1], reverse=True)]
    print("Category (Rank) & Normalized Pinning & # Apps")
    for category, normalized_pinning in sorted_normalized_category_counts:
        print("%", category + " (" +str(category_ranks.index(category) + 1) + ")",
            "&", normalized_pinning, "\%", "&", pinning_counts[category], "\\\\")
    return
    columns = ["Pinning category", "# Apps", "Dataset category", "# Apps"]
    data = []
    # print(dataset_category_counts)
    print("###########################################################")
    print(pinning_counts)
    # ROW LOGIC
    num_rows = 5 # Generate top 5
    num_rows = len(dataset_category_counts_sorted)
    for i in range(num_rows):
        # Drop row if category count is low (< 25 apps in category)
        if dataset_category_counts_sorted[i][1] < 25 and i >= len(pinning_counts):
            continue
        if i < len(pinning_counts):
            category_name, category_count = pinning_counts[i]
            normalized_pinning = round(category_count / dataset_category_counts[category_name], 2)
            data.append([category_name,
                str(category_count) + " (" + str(normalized_pinning) + ")",
                dataset_category_counts_sorted[i][0],
                dataset_category_counts_sorted[i][1]])
        else:
            data.append(['', '', dataset_category_counts_sorted[i][0],
            dataset_category_counts_sorted[i][1]])

    fig, axs = plt.subplots(1,1)
    df = pd.DataFrame(data, columns=columns)
    axs.axis('tight')
    axs.axis('off')
    axs.table(cellText=df.values,colLabels=df.columns,loc='center')
    plt.show()
    # Plot all pinning categories
    """
    fig, axs = plt.subplots(1,1)
    df = pd.DataFrame(pinning_counts, columns=["Category", "Pinning apps"])
    axs.axis('tight')
    axs.axis('off')
    axs.table(cellText=df.values,colLabels=df.columns,loc='center')
    plt.show()
    """


def fix_android(category):
    # Handle play details categories
    if type(category) == list:
        category = category[0]
        if category.startswith("GAME_"):
            return "GAME"
    return category

def get_category_by_popularity(pinning_packages, package_details):
    category_counts = defaultdict(int)
    for pack in pinning_packages:
        if pack in package_details and 'category' in package_details[pack]:
            category = fix_android(package_details[pack]['category'])
            category_counts[category] += 1
        else:
            category_counts["MISSING_CATEGORY"] += 1
            print("missed category:", pack)
    return category_counts
    return [(k,v) for k,v in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)]

def get_package_from_text(package_filter_file):
    if package_filter_file is None:
        return set()
    pack_filter = set()
    with open(package_filter_file, "r") as inf:
        if "android_" in package_filter_file:
            # Android split logic
            for line in inf.readlines():
                line = line.strip()
                pack_name = line.split('-')[0]
                pack_filter.add(pack_name)
        elif "ios_" in package_filter_file:
            # iOS split logic
            for line in inf.readlines():
                pack_name = line.strip()
                pack_filter.add(pack_name)
    return pack_filter

def get_category_counts_for_packages(packages, package_details):
    category_counts = defaultdict(int)
    for package_name in packages:
        if package_name in package_details:
            if 'category' in package_details[package_name]:
                category = fix_android(package_details[package_name]['category'])
                category_counts[category] += 1
            else:
                pass
                category_counts["MISSING_CATEGORY"] += 1
        else:
            print("No pack name key?", package_name)
            category_counts["MISSING_CATEGORY"] += 1
    return category_counts

def get_category_counts(package_details):
    category_counts = defaultdict(int)
    for pack, details in package_details.items():
        if 'category' in details:
            category = fix_android(details['category'])
            category_counts[category] += 1
        else:
            category_counts["MISSING_CATEGORY"] += 1
    categories_sorted_tuple = [(k,v) for k,v in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)]
    return categories_sorted_tuple, category_counts

def check_and_load(infile, default=""):
    if infile != default:
        with open(infile, "r") as inf:
            return json.load(inf)
    return default

if __name__ == "__main__":
    main()
