#!/usr/bin/env python3
import matplotlib
import venn
import json
import utils
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

MASTER_RESULT = "./csvs/MASTER_RESULT.csv"

CATEGORY_OUTPUT_FILE = "./pinning_by_category.pdf"

PLAY_DETAILS = "./play_details.json"
# Results rows:
# sha256,packageName,techniqueName,pinningFound,pins,pinsPaths,certs,certsPaths,extra

technique_label = {
"sina": "Sina",
"pinStringSearch": "String",
"dynamicTesting": "Dynamic",
"networkSecurityConfig": "NSC"
}

def main():
    print("THIS SCRIPT IS DEPRECATED, USE GENERATE_TOP_5_CATEGORY SCIPRT")
    return
    results = utils.get_result_from_csv(MASTER_RESULT)
    results_by_cat = defaultdict(lambda: defaultdict(int))
    play_details = {}
    with open(PLAY_DETAILS) as inf:
        play_details = json.load(inf)
    total_ctr = 0
    all_categories = set()
    # Get category wise APK couts
    category_counts = defaultdict(int)
    for package_name, app_details in play_details.items():
        if "category" not in app_details:
            print("No category info for:", package_name)
            continue
        category = app_details["category"]
        if len(category) > 1:
            print("Package with multiple categories:", package_name)
        category = category[0]
        if category.startswith("GAME"):
            category = "GAMING"
        category_counts[category] += 1
    print(category_counts)
    for technique, packages in results.items():
        for p in packages:
            try:
                total_ctr += 1
                category = play_details[p]["category"][0]
                if category.startswith("GAME"):
                    category = "GAMING"
                all_categories.add(category)
                results_by_cat[technique][category] += 1
            except KeyError:
                print("No Key:", p)
    all_categories = list(all_categories)
    all_categories.sort()
    data_map = {}
    for technique, category_distribution in results_by_cat.items():
        data_piece = []
        for category in all_categories:
            percentage = float(category_distribution[category] * 100)
            percentage = round(percentage / category_counts[category], 2)
            data_piece.append(percentage)
        data_map[technique_label[technique]] = data_piece
    df = pd.DataFrame(data_map, index=all_categories)

    print(df)

    # plot grouped bar chart
    # df.plot.bar(title='Techniques detecting pinning by category of apps', rot=75)
    fig, axs = plt.subplots(ncols=3, gridspec_kw=dict(width_ratios=[1,1,1]))
    sns.heatmap(df, annot=True, fmt='.3g', cmap='YlGnBu', ax=axs[0], yticklabels=True, cbar=False)
    sns.heatmap(df, annot=True, fmt='.3g', cmap='YlGnBu', ax=axs[1], yticklabels=False, cbar=False)
    sns.heatmap(df, annot=True, fmt='.3g', cmap='YlGnBu', ax=axs[2], yticklabels=False)
    fig.suptitle("Pinning found by category and techniques")
    for ax in axs.flat:
        plt.setp(ax.get_xticklabels(), rotation=0)
    plt.show()
    #plt.savefig(CATEGORY_OUTPUT_FILE)
    return

if __name__ == "__main__":
    main()
