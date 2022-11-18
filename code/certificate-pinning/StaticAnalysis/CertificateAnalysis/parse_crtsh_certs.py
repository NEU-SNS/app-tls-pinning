from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import os
from multiprocessing import Process
import base64
import fcntl
import json
import re, requests
import time
import urllib.request
import random
from os.path import exists

def search_crtsh(hash, type="sha256"):
    page = requests.get(
        "https://crt.sh/?spki" + type + "=" + hash).text
    ids = re.findall('<A href="\?id=(.*)">.*<\/A><\/TD>', page)
    return ids

input_search_pins = './rawData/searchPins.txt'

search_pins = {'sha1': set(), 'sha256': set()}
with open(input_search_pins, 'r') as sp_f:
    for l in sp_f.readlines():
        items = l.strip().split("/", 1)

        pin = items[1]
        # If we have pins in shaX/base64(HEX) format instead of shaX/HEX format
        if items[0] == "sha1" and len(items[1]) != 40:
            pin = base64.b64decode(items[1]).hex()
        elif items[0] == "sha256" and len(items[1]) != 64:
            pin = base64.b64decode(items[1]).hex()

        search_pins[items[0]].add(pin)

for s in search_pins:
    l = search_pins[s]
    random.shuffle(list(l))
    for pin in l:
        if exists("./certificatesCrawledStatic/" + pin + ".crt"):
            print("Skipping: ", pin)
            continue
        try:
            print("Trying to find pin: ", pin)
            ids = search_crtsh(pin, s)
            print(ids)
            time.sleep(5)
            if len(ids) > 0:
                urllib.request.urlretrieve("https://crt.sh/?d=" + ids[0], "./certificatesCrawledStatic/" + pin + ".crt")
                time.sleep(5)
        except Exception as e:
            print(e)
            pass