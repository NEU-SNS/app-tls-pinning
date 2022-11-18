#!/usr/bin/env python3
import argparse
import sys
from google_play_scraper import app
from google_play_scraper.exceptions import NotFoundError
import json
import time

# How much to sleep between requests for play details
SLEEP_SECONDS = 1

def main():
    parser = argparse.ArgumentParser(description='Download app details from play store.')
    parser.add_argument('--packs', help='List of packages, one package per line', type=str, nargs='+', required=True)
    args = parser.parse_args(sys.argv[1:])
    for pack_list in args.packs:
        get_play_details(pack_list)

def get_play_details(pack_list):
    results = {}
    with open(pack_list, "r") as inf:
        for line in inf.readlines():
            line = line.strip()
            print("Fetching:", line)
            try:
                results[line] = app(line)
            except NotFoundError as e:
                pass
            time.sleep(SLEEP_SECONDS)
            with open(pack_list + ".json", "w") as ouf:
                json.dump(results, fp=ouf, sort_keys=True, indent=2)


if __name__ == "__main__":
    main()
