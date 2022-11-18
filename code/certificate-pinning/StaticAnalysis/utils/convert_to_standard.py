# this script parses the result of TrustManager static analysis and does two tasks:
# 1) labels the sample based on a list of indicators that the user selects
# 2) produces a format that is agreed upon.
# An example of running this script (based on the best combination of indicators we found so far) is:
# python3 convert_to_standard.py [PATH\TO\analysis_res.csv] -output trustManager_standard_10k.csv -indicators generateCertificate setCertificateEntry
import csv
import json
import argparse
import os

fieldnames = ['sha256', 'packageName', 'techniqueName', 'pinningFound', 'pins', 'pinsPaths', 'certs', 'certsPaths', 'errors', 'extra']
analyzed_apks = {}


def contains_pinning(pinPaths, selected_indicators): #we are intersted in finding a combination of indicators, and hence this is an AND logic
    pins = True
    for indicator in selected_indicators:
        if indicator not in pinPaths:
            return False # make is false if one indicator is not present
    return True # all were present and hence True

def prune_duplicates(list_str):
    ret = []
    for string1 in list_str:
        if string1 not in ret:
            ret.append(string1)
    return ret

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

parser = argparse.ArgumentParser()
parser.add_argument('csv', type=str, help='dumps the result of the analysis in this folder if set', default="analysis_res.csv")
parser.add_argument('-output', type=str, help='dumps the result of the analysis in this folder if set', default="sina.csv")
parser.add_argument('-indicators', nargs='+', help='indicators to be used; separate them with a whitespace', required=True)

args = parser.parse_args()
output = open(args.output, 'w')
csvWriter = csv.DictWriter(output, delimiter=',', fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
csvWriter.writeheader()
if __name__=='__main__':
    load_csv(args.csv,analyzed_apks,'name')
    for name in analyzed_apks:
        techniqueName = ''
        pinPaths = {}
        extra = {'found_refs':0,'indicators':[]}
        apk = analyzed_apks[name]
        if apk[2] and apk[2]!='':
            pinPaths["inits"]= prune_duplicates(apk[2].split(";"))
        if apk[4] and apk[4]!='':
            pinPaths["setCertificateEntry"]= prune_duplicates(apk[4].split(";"))
        if apk[5] and apk[5]!='':
             pinPaths["generateCertificate"]= prune_duplicates(apk[5].split(";"))
        if len(pinPaths)>0:
            techniqueName = "trustManager"
        extra['found_refs'] = apk[3]
        if techniqueName != '':
            try:
                extra['indicators'] = list(pinPaths.keys())
                csvWriter.writerow({'sha256': apk[0],
                                    'packageName': apk[1],
                                    'techniqueName': techniqueName,
                                    'pinningFound': contains_pinning(pinPaths,args.indicators),
                                    'pins': '[]',
                                    'pinsPaths': json.dumps(list(pinPaths.values())),
                                    'errors': '[]',
                                    'certs': '[]',
                                    'certsPaths': '[]',
                                    'extra': json.dumps(extra)
                                    })
            except Exception as e:
                print(e)
