#!/usr/bin/env python3
import sys
import csv
csv.field_size_limit(sys.maxsize)
import argparse
import json
from OpenSSL.crypto import load_certificate, dump_certificate
from OpenSSL.crypto import FILETYPE_TEXT, FILETYPE_PEM

RN = "\\r\\n"
N = "\\n"

def main():
    parser = argparse.ArgumentParser(description='Generate pinned certificate information graphs/visualizations.')
    parser.add_argument('--result', help='Specify master result with results for all techniques combined.', type=str, nargs='?', required=True)
    args = parser.parse_args(sys.argv[1:])
    crt_ctr = 0
    successful = 0
    errors = 0
    with open(args.result) as inf:
        reader = csv.DictReader(inf, quoting=csv.QUOTE_MINIMAL)
        for row in reader:
            try:
                certs = json.loads(row["certs"])
            except:
                continue
            if len(certs) > 0:
                crt_ctr += 1
                if isinstance(certs, dict):
                    print("dict:", len(certs))
                    certs = list(certs.keys())
                elif isinstance(certs, list):
                    print("list:", len(certs))
                else:
                    print("Unknown", type(certs))
                certs = sorted(certs)
                cert_loaded = None
                for cert in certs:
                    new_cert = ""
                    if RN in cert:
                        for line in cert.split(RN):
                            new_cert += line + "\n"
                    elif N in cert:
                        for line in cert.split(N):
                            new_cert += line + "\n"
                    else:
                        new_cert = cert
                    try:
                        cert_loaded = load_certificate(FILETYPE_PEM, new_cert)
                    except Exception as e:
                        print("error", e)
                        print("Cert:", type(cert), cert)
                        print(len(cert))
                        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                        errors += 1
                    if cert_loaded is not None:
                        # print(dump_certificate(FILETYPE_TEXT, cert_loaded))
                        successful += 1
        print("Certs found:" + str(crt_ctr), "Parsed:", str(successful), "Errors parsing", str(errors))

if __name__ == "__main__":
    main()
