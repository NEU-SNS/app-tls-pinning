#!/usr/bin/env python3
import json
import os
import pprint
import r2pipe
import sys, traceback

from colorama import init

import csv
import argparse

from androguard.core import androconf
from androguard.core.bytecodes import apk
from androguard.core.bytecodes.axml import AXMLPrinter
from androguard.util import read
from androguard.session import Session, Load
from androguard.core.bytecodes.apk import APK
from zipfile import ZipFile

import re

def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))

# Strings of interest, the commented ones were usefull for double confirmation when building the ground truth
strings_of_interest = [
    "Lokhttp3copy/OkHttpClient$Builder;",
    "Lokhttp3/OkHttpClient$Builder;"]

white_list = [
    "Lokhttp3copy/OkHttpClient;",
    "Lokhttp3/OkHttpClient;",
    "Lcom/twitter/sdk/android;"]

found_indicators_dic = {}
header_programs = ["apkHash", "packageName", "caller"]

args = None
writer = None

def check_whiteList(subject,signals):
    for signal in signals:
        if re.search(signal,subject):
            return True
    return False

def find_cert_pinner(filename):
    num_refs = 0
    try:
        if filename:
            prYellow("Loading apk {}...".format(os.path.basename(filename)))
            prYellow("Please be patient, this might take a while.")

            filetype = androconf.is_android(filename)

            s = Session(export_ipython=True)

            h = s.add(filename)
            prYellow("Added file to session: SHA256::{}".format(h))
            packageName = ""
            if filetype == 'APK':
                prYellow("Loaded APK file...")
                a, d, dx = s.get_objects_apk(digest=h)
                print(">>> dx")
                print(dx)
                print()
                _a = APK(filename)
                packageName = _a.get_package()
                for signal in strings_of_interest:
                    if signal in dx.classes:
                        methods =  dx.classes[signal].get_methods()
                        for meth in methods:
                            if "certificatepinner" in meth.name.lower():
                                callee = signal[1:-1] + '.' + meth.name
                                print("usage of {}".format(callee))
                                for _, call, _ in meth.get_xref_from():
                                    if not trustManager_strs_xrefs.check_whiteList(call.class_name,white_list):
                                        num_refs = num_refs + 1
                                        print("|@#$|")
                                        caller = call.class_name[1:-1] + '.' + call.name
                                        if num_refs==1:
                                            found_indicators_dic[h] = [h, packageName, caller]
                                        else:
                                            found_indicators_dic[h] = [h, packageName, found_indicators_dic[h][2] + ";" + caller]
                                        prGreen("  called by -> {}".format(caller)) #remove the 'L' and ';' characters from the class name
                                        if args.source:
                                            try:
                                                src_code = call.source()
                                            except:
                                                    print("COULDN't DECOMPILE " + call.name)
            if h in found_indicators_dic:
                writer.writerow(found_indicators_dic[h])
            print("found " + str(num_refs) + " times in "+filename)
    except:
        print("there was an exception in processing " + filename)
        traceback.print_exc(file=sys.stdout)

if __name__ == "__main__":
    init() # output formatting init
    parser = argparse.ArgumentParser()
    parser.add_argument('name', type=str, help='the app apk file to be analyzed')
    parser.add_argument('-d', action='store_true', help='batch mode, the name is the dir for apks', default=False)
    parser.add_argument('-out', type=str, help='writes the summary into this file', default="certificate_pinner.csv")
    parser.add_argument('-source', action='store_true', help='print the source code', default=False)
    args = parser.parse_args()
    csv_file = open(args.out,"w")
    writer = csv.writer(csv_file)
    writer.writerow(header_programs)
    if args.d:
        apk_names = os.listdir(args.name)
        i = 0
        for apk_name in apk_names:
            apkfile = os.path.abspath(os.path.join(args.name,apk_name))
            find_cert_pinner(apkfile)
            i = i + 1
            print("finished processing "+str(i))
            csv_file.flush()
    else:
        find_cert_pinner(os.path.abspath(args.name))
    csv_file.close()
