#you need the the play-scraper package for this, install:
#pip3 install play-scraper
#run the script by typing "python3 app_info.py -id cy.com.ssm.wblemesos -o app_details.csv -v" where id is the package name.
import play_scraper
import argparse
import csv
import trustManager_strs_xrefs
import sys
import os
import re

from androguard.core import androconf
from androguard.core.bytecodes.apk import APK

apk_ids = {}
app_details = {}
details_to_store = ['category', 'description', 'free', 'developer_id', 'updated', 'installs', 'current_version', 'required_android_version', 'developer', 'developer_url', 'app_id', 'url'] #add other play_store attributes that you want here 
parser = argparse.ArgumentParser()

hash_pkg = {}

def info(package_name):
    ret = []
    details = None
    try:
        details = play_scraper.details(package_name) #this is the key api that allows information retrieval from playstore 
    except:
        print("couldn't retrive package details!")
    if details:
        for detail in details:
            if detail in details_to_store:
                if args.verbose:
                    print(str(details[detail]).encode(sys.stdout.encoding, errors='replace'))
                ret.append(str(details[detail]).encode(sys.stdout.encoding, errors='replace'))
    return ret

def find_package_name(apk_name):
    apkfile = os.path.abspath(apk_name)
    try:
        filetype = androconf.is_android(apkfile)
        if filetype == 'APK':
            _a = APK(apkfile)
            return _a.get_package()
    except:
        return None
        
parser.add_argument('-csv_filename', type=str, help='This option is for future support. Ideally, load the package names from a csv and get info for them')
parser.add_argument('-dirname', type=str, help='The directory that contains the apks')
parser.add_argument('-out_filename', type=str, help='saves the app details to this file.')
parser.add_argument('-id', type=str, help='The app id(package name) to look for.')
parser.add_argument('-apk', type=str, help='This option is for future support. The app apk to look for package name.')
parser.add_argument('-verbose', action='store_true', help='Continue from where you left off', default=False)
parser.add_argument('-m', action='store_true', help='Modify the csv_filename by storing package names extracted from the apk.', default=False)
args = parser.parse_args()

if args.id:
    app_details[args.id] = info(args.id)
elif args.csv_filename:
    trustManager_strs_xrefs.load_csv(args.csv_filename, apk_ids, 'name')
    for name in apk_ids:
        print("processing " + name)
        if name and re.search("\d+", name):
            apk_name = apk_ids[name][0].upper() + ".apk" #assumes the apk file name is the hash
            if args.dirname:
                apkfile = os.path.abspath(os.path.join(args.dirname,apk_name))
                print(apkfile)
                package_name = find_package_name(apkfile)
                if package_name and not args.m: #if the package names are not known, pass this option to the script
                    app_details[package_name] = info(package_name)
                if args.m:
                    apk_ids[name][1] = package_name
            else:
                print("dirname for the apk files is needed if the name is not in package name format!")
        elif name and re.search("\w.\w.*", name) and not args.m:
            app_details[name] = info(name)
        else:
            print("I don't handle such names right now: "+name)
    if args.m:
        trustManager_strs_xrefs.persist_csv(args.csv_filename,apk_ids, ["hash","name","pin_method","found_refs"])
            
elif args.apk:
    package_name = find_package_name(args.apk)
    print(package_name)
    if package_name:
        app_details[package_name] = info(package_name)
        
# print(app_details)
if args.out_filename and not args.m:
    print("storing to "+args.out_filename+"...")
    trustManager_strs_xrefs.persist_csv(args.out_filename,app_details, details_to_store)