#!/usr/bin/env python3
import os
import sys
from multiprocessing import Process
from collections import defaultdict

TRANCO = "tranco_5Y6XN.csv"
USER_AGENT = "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.58 Mobile Safari/537.36"

def fetch_page(domain):
    os.system("wget -A" + USER_AGENT + " -L " + domain + "-O " + domain + ".page")

def main():
    with open(TRANCO, "r") as inf:
        processes = []
        for line in inf.readlines():
            print(line)
            continue
            p = Process(target=fetch_homepage, args=(domain))
            processes.append(p)
            p.start()
            while len(processes) >= 16:
                for p in processes:
                    p.join(0.1)
                    if not p.is_alive():
                        processes.remove(p)
        for p in processes:
            p.join()

# Boilerplate
if __name__ == "__main__":
    main()
