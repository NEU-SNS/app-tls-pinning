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
from zipfile import ZipFile

import re

def create_if_not_exists_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))

# Strings of interest, the commented ones were usefull for double confirmation when building the ground truth
strings_of_interest = [
    # "Ljavax/net/ssl/X509TrustManager;",
    # "Ljavax/net/ssl/SSLSocket;",
    # "Ljavax/net/ssl/SSLSocketFactory;",
    "Ljavax/net/ssl/TrustManagerFactory;",
    "Ljavax/net/ssl/SSLContext;",
    "Ljava/security/cert/CertificateFactory;",
    "Ljava/security/KeyStore;"]

white_list = [
    "javax/net/ssl",
    "com/google/android",
    "okhttp\d?/",
    "org/apache/http"] #add the new whitelists

init_methods = ["<init>", "init"]
certificate_methods = ["setCertificateEntry", "generateCertificate", "generateCertificates"]

indicator1 = 'init\(.*\,.*\,.*\)'
indicator3 = "Certificate"
indicator2 ='(init\(\s*([^0][^,\(]+|[^0][^,]+\([^\(]+\))\s*\))' #wouldn't match init(0) or alikes; the param could to be a variable or a method call but there has to be only one param

found_indicators_dic = {}
programs_analysis_dic = {}
certificate_indicators = ["","",""]
header_indic = ["caller","TrustManagerFactory.init","SSLContext.init","init3_2arg","init1_1arg", "certificate"]
header_programs = ["hash","name","pin_method","found_refs","setCertificateEntry","generateCertificate"]
csv_filename = "analysis_res.csv"

contains_pinning = ""
contains_pinning_func = ""

args = None

num_refs = 0

def persist_csv(csv_filename,dictionary, header):
    csv_file = open (csv_filename,"w")
    writer = csv.writer(csv_file)
    writer.writerow(header)
    for i in dictionary.values():
        writer.writerow(i)
    csv_file.close()

def load_csv(csv_filename, dictionary, keyCol):
    if not os.path.exists(csv_filename):
        csv_file = open(csv_filename,"w+")
    else:
        csv_file = open(csv_filename,"r")
    reader = csv.DictReader(csv_file)
    for row in reader:
        # print(row[keyCol])
        dictionary[row[keyCol]] = list(row.values())
    csv_file.close()

def check_whiteList(subject,signals):
    for signal in signals:
        if re.search(signal,subject):
            return True
    return False


def xref_analysis(filename):
    global num_refs
    try:
        if filename:
            prYellow("Loading apk {}...".format(os.path.basename(filename)))
            prYellow("Please be patient, this might take a while.")

            filetype = androconf.is_android(filename)

            prGreen("Found the provided file is of type '{}'".format(filetype))

            s = Session(export_ipython=True)

            h = s.add(filename)
            prYellow("Added file to session: SHA256::{}".format(h))

            if filetype == 'APK':
                prGreen("Loaded APK file...")
                a, d, dx = s.get_objects_apk(digest=h)
                print(">>> dx")
                print(dx)
                print()
                for i in range(0,len(strings_of_interest)): #loop over the class names we are interested in, and do xref analysis if the package contains that class
                    signal = strings_of_interest[i]
                    if signal in dx.classes:
                        for meth in dx.classes[signal].get_methods(): # we need the meth object to find the method name, hence we need to loop over all method names to find out those we are intersted in
                            # meth_anal = dx.classes[signal].get_method_analysis(meth.get_method())
                            # print(meth.get_method().get_information()) #wouldn't work
                            if meth.name in init_methods: # find the xrefs to this indicator
                                meth_name = str(meth.name)
                                callee = signal[1:-1] + '.' + meth_name
                                num_refs = num_refs + 1
                                print("usage of {}".format(callee))
                                for _, call, _ in meth.get_xref_from():
                                    call_class_name = str(call.class_name)
                                    if not check_whiteList(call_class_name,white_list): #skip those that we know are false positive
                                        print("|@#$|")
                                        caller_class_name = call_class_name[1:-1]
                                        caller = caller_class_name + '.' + str(call.name)
                                        if caller_class_name in found_indicators_dic: #the caller exists, so just update the indicators list
                                            found_indicators_dic[caller_class_name][i+1] = str(call.name)
                                        else:  #make the entry in the hashmap for this caller
                                            evidence = ["N"]*6
                                            evidence[0] = caller_class_name
                                            evidence[i+1] = str(call.name)
                                            found_indicators_dic[caller_class_name] = evidence
                                        prYellow("  called by -> {}".format(caller)) #remove the 'L' and ';' characters from the class name
                                        # print(call.get_information())
                                        # sys.stdout = open("found_srcs.java", "w")
                                        try:
                                            src_code = call.source() # decompile, so we can check the parameters' value. It seems there is no way to get the result in a string, and redirection in the code messes up because of formatting. So, the user need to redirect the decompiled result to a file.
                                        except:
                                            print("COULDN't DECOMPILE " + caller)
                                    # sys.stdout.close()
                            elif meth.name in certificate_methods:
                                meth_name = str(meth.name)
                                index = certificate_methods.index(meth.name)
                                callee = signal[1:-1] + '.' + meth_name
                                print("usage of {}".format(callee))
                                for _, call, _ in meth.get_xref_from():
                                    call_class_name = str(call.class_name)
                                    if not check_whiteList(call_class_name,white_list):
                                        print("|@#$|")
                                        caller_certificate = call_class_name[1:-1] + '.' + str(call.name)
                                        if certificate_indicators[index]!="":
                                            certificate_indicators[index] = certificate_indicators[index] + ";" + caller_certificate
                                        else:
                                            certificate_indicators[index] = caller_certificate
                                        prYellow("  called by -> {}".format(caller_certificate))
                                        try:
                                            src_code = call.source()
                                        except:
                                            traceback.print_exc(file=sys.stdout)
                                            print("COULDN't DECOMPILE ")
    finally:
        programs_analysis_dic[h] = [h,args.name,"",num_refs,certificate_indicators[0],certificate_indicators[1]] # after evaluation, we found that a combination of calls to certificate methods is the best indicator so just keep them
        persist_csv(args.db, programs_analysis_dic, header_programs)
        persist_csv(csv_filename, found_indicators_dic, header_indic)

def find_indicator_context_init(indicator, func):
    found_pattern = re.findall(indicator,func)# search for a method with three arguments [a-z]\w*\(.*\,.*\,.*\). Here, we're looking for SSLContext init. The trustmanager init takes 1 argument
    if found_pattern:
        for pat in found_pattern:
            params = pat.split(',')
            trustM_param = params[1].strip()
            if trustM_param!='0': #TODO: for conversion cases
                prGreen("found indicator -> {}".format(pat))
                return True
            else:
                prYellow("found indicator with null param -> {}".format(pat))
    return False

def update_dictionary(caller,ctx_init_stat, tm_init_stat, cert_stat):
    if caller in found_indicators_dic:
        if ctx_init_stat:
            found_indicators_dic[caller][3] = 'Y'
        if tm_init_stat:
            found_indicators_dic[caller][4] = 'Y'
        if cert_stat:
            found_indicators_dic[caller][5] = 'Y'
        if found_indicators_dic[caller][1]!='N' and found_indicators_dic[caller][2]!='N' and found_indicators_dic[caller][3]!='N' and found_indicators_dic[caller][4]!='N':
            return True
    else:
        prRed("caller not in dictionary list")
    return False

def find_indicators(indicator, func):
    cert_ind = re.findall(indicator,func)
    if cert_ind:
        prGreen("found indicator -> {}".format(cert_ind[0]))
        return True
    return False

def configure_module(options):
    global csv_filename
    if not options.name:
        options.name = str(options.sid)
    csv_filename = os.path.join(options.o,options.name + "_" + "analysis" + ".csv")

if __name__ == "__main__":
    init() # output formatting init
    parser = argparse.ArgumentParser()
    parser.add_argument('app_name', type=str, help='the app apk file to be analyzed')
    parser.add_argument('-p', type=str, help='If set, processes a decompiled app source code snippets. The source code snippet should be produced by this program in a previous run.')
    parser.add_argument('-name', help='The app name, either this or a max ID should be inputted.')
    parser.add_argument('-sid', type=int, help='id for an app that doesnt have a name', default=1)
    parser.add_argument('-o', type=str, help='dumps the result of the analysis in this folder if set', default="analysis")
    parser.add_argument('-db', type=str, help='appends the summary into this file', default="analysis_res.csv")
    parser.add_argument('--printsrc', type=bool, help='Will print the method that applies certificate pinning if found one', default=False)
    args = parser.parse_args()
    configure_module(args)

    if args.p: #this phase would be optional, since the xref_analysis is accurate enough; we won't need to check the source code and parameters
        file = open(args.p,mode='r',encoding="utf8")
        file_contents = file.read()
        funcs_text = file_contents.split('|@#$|') # split functions and look for indicators in them
        usage_txt = "usage of (.*)\n"
        caller_txt = "called by -> (.*)\n"
        checked_usage = ""
        checked_caller = ""
        # # print(file_contents)
        load_csv(csv_filename, found_indicators_dic, 'caller')
        load_csv(args.db, programs_analysis_dic, 'name')
        # print(found_indicators_dic)
        funcs_count = 0
        for func in funcs_text: #the functions are separated using |@#$|
            found_us=re.findall(usage_txt,func)
            if found_us:
                checked_usage = found_us[0]
                print(checked_usage)
            found_caller=re.findall(caller_txt,func)
            if found_caller: #extract the caller name from the source code; that's the convention that the previous phase had
                checked_caller = found_caller[0]
                funcs_count = funcs_count + 1
                print(checked_caller)
                checked_caller = checked_caller.split(".")[0] # use the class name instead of the method itself
            else:
                prRed("WARNING, there was no caller name in the function snippet!")
            #check the indicators in the source code; see the top of the file for the patterns
            found_indic1 = find_indicator_context_init(indicator1, func)
            found_indic2 = find_indicators(indicator2, func)
            found_indic3 = find_indicators(indicator3, func)
            if found_indic1 or found_indic2 or found_indic3: #keep an entry in the csv only if at least one indicator is found
                if update_dictionary(checked_caller,found_indic1,found_indic2,found_indic3):
                    if contains_pinning:
                        contains_pinning = contains_pinning + ";" + checked_caller
                    else:
                        contains_pinning = checked_caller
                    contains_pinning_func = func
                # prYellow(func)
            else:
                prYellow("no indicator!")
        persist_csv(csv_filename, found_indicators_dic, header_indic)
        print()
        if contains_pinning!="":
            if args.name in programs_analysis_dic:
                programs_analysis_dic[args.name][2] = contains_pinning
            else:
                programs_analysis_dic[args.name] = ["",args.name,contains_pinning,funcs_count]
            persist_csv(args.db, programs_analysis_dic, header_programs)
            if args.printsrc:
                print(contains_pinning_func)
            prGreen("FOUND PINNING in {}!".format(contains_pinning))
        else:
            prYellow("Didnt find pinning in {}!".format(args.name))
    else:
        load_csv(args.db, programs_analysis_dic, 'hash')
        xref_analysis(args.app_name)
