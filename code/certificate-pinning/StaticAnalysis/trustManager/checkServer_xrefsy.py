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
import trustManager_strs_xrefs

def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))

# Strings of interest, the commented ones were usefull for double confirmation when building the ground truth
_trustmanager_interfaces = [
    'Ljavax/net/ssl/TrustManager;', 'Ljavax/net/ssl/X509TrustManager;']

white_list = [
    # "Lokhttp3copy/OkHttpClient;",
    ]
    
found_indicators_dic = {}
header_programs = ["apkHash", "packageName", "custom_TrustManager", "checkServerTrusted", "empty", "count","source_code"]

args = None    
writer = None

def _get_method_instructions(_method): #from mallodroid
    _code = _method.get_code()
    _instructions = []
    if _code:
        _bc = _code.get_bc()
        for _instr in _bc.get_instructions():
            _instructions.append(_instr)
    return _instructions

def _returns_true(_method): #from mallodroid
    _instructions = _get_method_instructions(_method)
    if len(_instructions) == 2:
        _i = "->".join(
            [_instructions[0].get_output(), _instructions[1].get_name() + "," + _instructions[1].get_output()])
        _i = _i.replace(" ", "")
        _v = _instructions[0].get_output().split(",")[0]
        _x = "{:s},1->return,{:s}".format(_v, _v)
        return _i == _x
    return False

def _returns_void(_method): #from mallodroid
    _instructions = _get_method_instructions(_method)
    if len(_instructions) == 1:
        return _instructions[0].get_name() == "return-void"
    return False
    
def _has_signature(_method, _signatures): #from mallodroid
    _name = _method.name
    _return = _method.get_information().get('return', None)
    _params = [_p[1] for _p in _method.get_information().get('params', [])]
    _access_flags = _method.get_access_flags_string()

    for _signature in _signatures:
        if (_access_flags == _signature['access_flags']) \
                and (_name == _signature['name']) \
                and (_return == _signature['return']) \
                and (_params == _signature['params']):
            return True
    return False

def _class_implements_interface(_class, _interfaces): #from mallodroid
    # print(_class.implements)
    # print(_interfaces)
    return (_class.implements and any([True for i in _interfaces if i in _class.implements]))

def _check_trust_manager(_class):
    _check_server_trusted = {'access_flags': 'public', 'return': 'void', 'name': 'checkServerTrusted',
                             'params': ['java.security.cert.X509Certificate[]', 'java.lang.String']}
    _custom_trust_manager = {'implements_trust_manager': False, 'check_server_trusted': None, 'empty': False}
    if _class_implements_interface(_class, _trustmanager_interfaces):
        methods =  _class.get_methods()
        _custom_trust_manager['implements_trust_manager'] = True
        for _method in methods:  
            if _has_signature(_method.get_method(), [_check_server_trusted]):
                _custom_trust_manager['check_server_trusted'] = _method
                if _returns_true(_method.get_method()) or _returns_void(_method.get_method()):
                    _custom_trust_manager['empty'] = True
                break
    # print(_custom_trust_manager)
    return _custom_trust_manager
    
def analyze_apk(filename):
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
                for _class in dx.classes:
                        target = None
                        check_server = ""
                        analysis =  _check_trust_manager(dx.classes[_class])
                        source = ""
                        if analysis['implements_trust_manager']:
                            #if not trustManager_strs_xrefs.check_whiteList(_class,white_list):
                            target = _class[1:-1]
                            num_refs = num_refs + 1
                        if analysis['check_server_trusted']:
                            check_server = analysis['check_server_trusted'].name
                        if not analysis['empty'] and analysis['check_server_trusted']:
                            if args.source:
                                try:
                                    # src_code = analysis['check_server_trusted'].show()
                                    source = analysis['check_server_trusted'].get_method().get_source()
                                    print(source)
                                except:
                                        #print(dir(analysis['check_server_trusted']))
                                        traceback.print_exc(file=sys.stdout)
                                        print("COULDN't DECOMPILE " + analysis['check_server_trusted'].name)
                        if target:
                            if num_refs==1:
                                found_indicators_dic[h] = [h, packageName, target, check_server, str(analysis['empty']), 1, source]
                            else:
                                found_indicators_dic[h] = [h, packageName, found_indicators_dic[h][2]+";"+target, found_indicators_dic[h][3]+";"+check_server, found_indicators_dic[h][4] +";" +  str(analysis['empty']), num_refs, found_indicators_dic[h][6] + "|@#$|" + source]
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
    parser.add_argument('-out', type=str, help='writes the summary into this file', default="check_server_trusted.csv")
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
            analyze_apk(apkfile)
            i = i + 1
            print("finished processing "+str(i))
            csv_file.flush()
    else:
        analyze_apk(os.path.abspath(args.name))
    csv_file.close()
