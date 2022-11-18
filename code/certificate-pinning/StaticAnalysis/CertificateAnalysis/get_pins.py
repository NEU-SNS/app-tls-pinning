import csv
import sys
import json

csv.field_size_limit(sys.maxsize)

fieldnames = ['OS', 'sha256', 'packageName', 'techniqueName', 'pinningFound', 'certsFound', 'pins', 'pinsPaths',
              'certs', 'certsPaths', 'errors', 'extra']
for f in ["rawData/androidStaticAnalysis.txt", "rawData/iosStaticAnalysis.txt"]:
    with open(f, 'r') as output:
        csvReader = csv.DictReader(output, delimiter=',', fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        for row in csvReader:
            if row['pinningFound'] == "True":
               pins = json.loads(row['pins'])
               for p in pins:
                   print(p)
