#This script analyzes the paths to the pinning methods, and extract some library names. The input should be the found pins containing a column that has the path value.
#The script lets you set the column name. After processing, it produces two files. The name_freq.csv file contains the names, their frequencies and all paths containing that name.
import argparse
import csv
import sys
import os

parser = argparse.ArgumentParser()
parser.add_argument('in_csv', type=str, help='The csv file with paths doing pinning')
parser.add_argument('-col_name', type=str, help='where to store the results', default="setCertificateEntry")
parser.add_argument('-out_csv', type=str, help='where to store the results', default="path_freq.csv")
parser.add_argument('-out2_csv', type=str, help='where to store the results', default="name_freq.csv")
args = parser.parse_args()
paths = []
read_file = open(args.in_csv,"r")
reader = csv.DictReader(read_file)
for row in reader:
    paths.append(row[args.col_name]) #read the path names based on the user provided column name.
upaths_freq = {}
for path in paths: # count the repititions of a particular path
    if path not in upaths_freq:
        upaths_freq[path] = 1
    else:
        upaths_freq[path] = upaths_freq[path] + 1
paths.sort() # sort the path, so all the paths sharing the same prefix are grouped and we can analyze all of them in a single loop
app_names = {} 
last_name = ""
for path in paths:
 name_splits=path.split("/")
 if len(name_splits)>1:
   name = name_splits[1] # we assume it is the second level domain name, and hence the library name
   if name!=last_name: # since the path names are sorted, we only need to check they are equal to the last name
     if name not in app_names:
        app_names[name] = [1, [path]]
     else:
        app_names[name][0] = app_names[name][0] + 1
        if path not in app_names[name][1]: #if the path is not new, add it
           app_names[name][1].append(path)
     name = last_name

write_file = open(args.out_csv,"w")
writer = csv.DictWriter(write_file, fieldnames=["path","freq"] ,delimiter=';', quoting=csv.QUOTE_MINIMAL)
for row in upaths_freq:
    writer.writerow({'path': row, 'freq':upaths_freq[row]})
write_file.close()

write_file = open(args.out2_csv,"w")
writer = csv.DictWriter(write_file, fieldnames=["name","freq", "path"] ,delimiter=';', quoting=csv.QUOTE_MINIMAL)
for row in app_names:
    writer.writerow({'name': row, 'freq':app_names[row][0], 'path':app_names[row][1]})
write_file.close()