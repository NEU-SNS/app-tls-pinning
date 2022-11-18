from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import os
from multiprocessing import Process
import base64
import fcntl

input_dir_ctlogs = "/net/data/ctlogs/accs/certificates"
input_search_pins = 'searchPins.txt'

# Look for all .CSV CT logs
csvs = set()
for root, dirs, files in os.walk(input_dir_ctlogs):
    for f in files:
        x = os.path.join(root, f)
        if x.endswith(".csv"):
            csvs.add(x)

search_pins = {'sha1': set(), 'sha256': set()}
with open(input_search_pins, 'r') as sp_f:
    for l in sp_f.readlines():
        items = l.strip().split("/", 1)
        
        pin = items[1]  
        # If we have pins in shaX/HEX format instead of shaX/base64(HEX)
        if items[0] == "sha1" and len(items[1]) == 40:
            pin = base64.b64encode(bytes.fromhex(items[1])).decode()
        elif items[0] == "sha256" and len(items[1]) == 64:
            pin = base64.b64encode(bytes.fromhex(items[1])).decode()
        
        search_pins[items[0]].add(pin)


def get_pem_ctlog_record(record):
    start = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    return start + "\n" + record.split(",")[5] + "\n" + end


def get_spki_bytes(pem):
    return x509.load_pem_x509_certificate(pem.encode(), default_backend()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def get_base64_encoded_hash(input_bytes, hash_type):
    if hash_type == 'sha1':
        return base64.b64encode(hashlib.sha1(input_bytes).digest()).decode()
    elif hash_type == 'sha256':
        return base64.b64encode(hashlib.sha256(input_bytes).digest()).decode()
    assert False


def process_ctlog_file(csv_file):
    with open(csv_file) as cf:
        for line in cf:
            line = line.strip()
            try:
                assert len(line.split(",")) == 9
            except AssertionError:
                continue

            # First get PEM certificate
            pem = get_pem_ctlog_record(line)

            # Get pin
            spki_bytes = get_spki_bytes(pem)
            sha1_pin = get_base64_encoded_hash(spki_bytes, 'sha1')
            sha256_pin = get_base64_encoded_hash(spki_bytes, 'sha256')

            # Are we looking for this pin's certificate?
            if sha1_pin in search_pins['sha1'] or sha256_pin in search_pins['sha256']:
                with open('successPins.txt', 'a') as ep:
                    fcntl.flock(ep, fcntl.LOCK_EX)
                    ep.write(line + "," + sha1_pin + "," + sha256_pin + "\n")
                    fcntl.flock(ep, fcntl.LOCK_UN)
    print("Done processing: ", csv_file)


processes_internal = []
for csv in csvs:
    p = Process(target=process_ctlog_file, args=(csv,))
    processes_internal.append(p)
    p.start()
    while len(processes_internal) >= 72:
        for p in processes_internal:
            p.join(0.1)
            if not p.is_alive():
                processes_internal.remove(p)
for p in processes_internal:
    p.join()
print("Done!")
