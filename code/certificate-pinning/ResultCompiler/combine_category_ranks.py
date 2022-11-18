#!/usr/bin/env python3
import sys
from collections import defaultdict
import argparse
import json

AND_CAT_MAP = {
    "GAME": "Games",
    "PRODUCTIVITY": "Productivity",
    "BUSINESS": "Business",
    "COMMUNICATION": "Communication",
    "FINANCE": "Finance",
    "EDUCATION": "Education",
    "SOCIAL": "Social",
    "HEALTH_AND_FITNESS": "Health",
    "TRAVEL_AND_LOCAL": "Travel",
    "LIFESTYLE": "Lifestyle",
    "MISSING_CATEGORY": "MISSING",
    "MUSIC_AND_AUDIO": "Music",
    "BOOKS_AND_REFERENCE": "Books",
    "ENTERTAINMENT": "Entertainment",
    "FOOD_AND_DRINK": "Food",
    "PHOTOGRAPHY": "Photography",
    "TOOLS": "Tools",
    "MAPS_AND_NAVIGATION": "Navigation",
    "NEWS_AND_MAGAZINES": "News",
    "SHOPPING": "Shopping",
    "SPORTS": "Sports",
    "WEATHER": "Weather",
    "PERSONALIZATION": "Personalization*"
}

IOS_CAT_MAP = {
    "Photo & Video": "Photography",
    "Social Networking": "Social",
    "Food & Drink": "Food",
    "Health & Fitness": "Health",
    "Graphics & Design": "Graphics*",
    "Medical": "Medical*",
    "Reference": "Reference*",
}

"""
Each json is a dict of category name to number of apps in that category
"""

COMMON_DATASET_SIZE = 575
POPULAR_DATASET_SIZE = 1000
RANDOM_DATASET_SIZE = 1000

def main():
    parser = argparse.ArgumentParser(description='Create heatmap for top 5 categories that pin')
    parser.add_argument('--andcommon', help='Result for and common 600', type=str, nargs='?', default="", required=True)
    parser.add_argument('--andrandom', help='Result for and random 1k', type=str, nargs='?', default="", required=True)
    parser.add_argument('--andpopular', help='Result for and popular 1k', type=str, nargs='?', default="", required=True)
    parser.add_argument('--ioscommon', help='Result for ios common 600', type=str, nargs='?', default="", required=True)
    parser.add_argument('--iosrandom', help='Result for ios random 1k', type=str, nargs='?', default="", required=True)
    parser.add_argument('--iospopular', help='Result for ios popular 1k', type=str, nargs='?', default="", required=True)
    parser.add_argument('--ranks', help='Number of rows to print', type=int, nargs='?', default=10)
    args = parser.parse_args(sys.argv[1:])
    try:
        with open(args.andcommon, "r") as inf:
            android_common = clean_android(json.load(inf))
        with open(args.andrandom, "r") as inf:
            android_random = clean_android(json.load(inf))
        with open(args.andpopular, "r") as inf:
            android_popular = clean_android(json.load(inf))
        with open(args.ioscommon, "r") as inf:
            ios_common = json.load(inf)
        with open(args.iosrandom, "r") as inf:
            ios_random = json.load(inf)
        with open(args.iospopular, "r") as inf:
            ios_popular = json.load(inf)
    except Exception as e:
        print("Failed to open json file...", e)
        return
    print("Android common, popular, random then iOS common, popular, random")
    android_common = [(fix_android_category(k),v) for k,v in sorted(android_common.items(), key=lambda x: x[1], reverse=True)]
    android_popular = [(fix_android_category(k),v) for k,v in sorted(android_popular.items(), key=lambda x: x[1], reverse=True)]
    android_random = [(fix_android_category(k),v) for k,v in sorted(android_random.items(), key=lambda x: x[1], reverse=True)]
    ios_common = [(fix_ios_category(k),v) for k,v in sorted(ios_common.items(), key=lambda x: x[1], reverse=True)]
    ios_popular = [(fix_ios_category(k),v) for k,v in sorted(ios_popular.items(), key=lambda x: x[1], reverse=True)]
    ios_random = [(fix_ios_category(k),v) for k,v in sorted(ios_random.items(), key=lambda x: x[1], reverse=True)]
    a_com = 0
    a_pop = 0
    a_ran = 0
    i_com = 0
    i_pop = 0
    i_ran = 0
    for i in range(args.ranks):
        a_com += android_common[i][1]
        a_pop += android_popular[i][1]
        a_ran += android_random[i][1]
        i_com += ios_common[i][1]
        i_pop += ios_popular[i][1]
        i_ran += ios_random[i][1]
        print(str(i+1), "&",
                android_common[i][0]+" "+str(int(int(android_common[i][1])*100/COMMON_DATASET_SIZE))+"\\%", "&", \
                android_popular[i][0]+" "+str(int(int(android_popular[i][1])*100/POPULAR_DATASET_SIZE))+"\\%", "&", \
                android_random[i][0]+" "+str(int(int(android_random[i][1])*100/RANDOM_DATASET_SIZE))+"\\%", "&", \
                ios_common[i][0]+" "+str(int(int(ios_common[i][1])*100/COMMON_DATASET_SIZE))+"\\%", "&", \
                ios_popular[i][0]+" "+str(int(int(ios_popular[i][1])*100/POPULAR_DATASET_SIZE))+"\\%", "&", \
                ios_random[i][0]+" "+str(int(int(ios_random[i][1])*100/RANDOM_DATASET_SIZE))+"\\%", "\\\\")
    print("And for now:", a_com/COMMON_DATASET_SIZE, a_pop/POPULAR_DATASET_SIZE, a_ran/RANDOM_DATASET_SIZE)
    print("iOS for now:", i_com/COMMON_DATASET_SIZE, i_pop/POPULAR_DATASET_SIZE, i_ran/RANDOM_DATASET_SIZE)

def fix_android_category(cat):
    if cat in AND_CAT_MAP:
        return AND_CAT_MAP[cat]
    return cat

def fix_ios_category(cat):
    if cat in IOS_CAT_MAP:
        return IOS_CAT_MAP[cat]
    return cat

# Drop all "MISSING_CATEGORY" ones
def clean_android(category_ranks):
    ret_dict = {}
    for category, count in category_ranks.items():
        if category != "MISSING_CATEGORY":
            ret_dict[category] = count
    return ret_dict

if __name__ == "__main__":
    main()
