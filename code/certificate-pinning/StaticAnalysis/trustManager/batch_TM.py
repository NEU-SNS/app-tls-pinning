import json
import os
import subprocess
import pprint
import r2pipe
import sys
from colorama import init

from androguard.core import androconf
from androguard.core.bytecodes.apk import APK

import argparse
import csv
import trustManager_strs_xrefs

import re
import zipfile

#Get the apk directory, and a starting id. Use the id to create the source file and provide that to the second run on the apk. Output the ending id after you finished!
cmd = None
if sys.platform=="linux":
    cmd = ["python3", "trustManager_strs_xrefs.py"]
else:
    cmd = "python3 trustManager_strs_xrefs.py"

programs_analysis_dic = {}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('dirname', type=str, help='The directory that contains the apks')
    parser.add_argument('-sid', type=int, help='The starting id to be assigned to the processed apps.',default=1)
    parser.add_argument('-srcdir', type=str, help='The source directory for storage of decompiled code', default="sources")
    parser.add_argument('-cont', action='store_true', help='Continue from where you left off', default=False)
    parser.add_argument('-csv_filename', type=str, help='reads the last session progress from this if -continue is set', default="analysis_res.csv")
    args = parser.parse_args()
    trustManager_strs_xrefs.load_csv(args.csv_filename, programs_analysis_dic, 'hash') #change to name if the app files use names instead of hash
    init() # output formatting init
    apk_names = os.listdir(args.dirname)
    i = args.sid
    for apk_name in apk_names:
        package_name = ""
        apkfile = os.path.abspath(os.path.join(args.dirname,apk_name))
        filetype = androconf.is_android(apkfile)
        if filetype == 'APK': #analyze only if the file is of type APK
            try:
                _a = APK(apkfile)
            except zipfile.BadZipFile:
                print("APK broken, bad zip file:", apk_name)
                continue
            package_name = _a.get_package() #retrieve the package name, would become handy later
            if args.cont and apk_name[:-4].lower() in programs_analysis_dic: #skip the analysis if the app already exists in the result csv, would be really helpful if the execution was interrupted
                print(package_name + ": " + apk_name + " been already analyzed!")
            else:
                src_file = os.path.join(args.srcdir,str(i)+".java") # store the source code in a file with an index
                std_f = open(src_file,"w+")
                item_cmd = None
                if sys.platform=="linux":
                    item_cmd = cmd.copy()
                    item_cmd.append(apkfile)
                    item_cmd.append("-name")
                    item_cmd.append(package_name)
                else:
                    item_cmd = cmd + ' ' + apkfile + ' -name' + ' ' + package_name
                print("Processing " + apk_name)
                print("XRef and decompilation phase... ")
                process = subprocess.Popen(item_cmd, stdout=std_f, stderr=std_f) #redirect the output that is the decompiled source code to the file configured above
                print("pid is "+str(process.pid))
                process.wait() #wait till the xref analysis and decompilation finishes
                item_cmd2 = None
                if sys.platform=="linux":
                    item_cmd2 = cmd.copy()
                    item_cmd2.append(apkfile)
                    item_cmd2.append("-p")
                    item_cmd2.append(src_file)
                    item_cmd2.append('-name')
                    item_cmd2.append(package_name)
                else:
                    item_cmd2 = cmd + ' ' + apkfile + ' -p ' + src_file + ' -name ' + package_name # use -p option to check the source code for patterns including the parameters not being null
                process2 = subprocess.Popen(item_cmd2)
                print("Indicators check phase, pid " + str(process2.pid))
                process2.wait()
                i = i + 1
        else:
            print(apkfile+" is "+"not an APK file!")
    # process = subprocess.Popen(cmd2, stdout=file, stderr=file)
    print("processed " + str(i-args.sid) + " in total!")
