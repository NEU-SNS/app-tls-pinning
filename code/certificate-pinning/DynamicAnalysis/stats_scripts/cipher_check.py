#!/usr/bin/env python3
import os
import json
import csv
import sys
import multiprocessing
from collections import defaultdict
import json
import pyshark
import lxml

CIPHER_EXTENSION = ".cipher"

# Need to change this based on what client IPs we expect
CLIENT_SUBNET_PREFIX_1 = "10.42.0"
CLIENT_SUBNET_PREFIX_2 = "192.168.2"

def generate_cipher_result(pcap, browser_name):
    out_dir = "/".join(pcap.split("/")[:-1])
    result_file = out_dir + "/" + browser_name + CIPHER_EXTENSION
    client_hellos = get_client_hello_streams(pcap)
    weak_ciphers = set()
    problematic = set()
    forward_secret = set()
    for ip, this_client_hellos in client_hellos.items():
        if ip.startswith(CLIENT_SUBNET_PREFIX_1) or ip.startswith(CLIENT_SUBNET_PREFIX_2):
            for packet in this_client_hellos:
                if not hasattr(packet, 'tls'):
                    continue
                if hasattr(packet.tls, 'handshake_extensions_server_name'):
                    dst = packet.tls.handshake_extensions_server_name
                else:
                    dst = "IP:" + packet.ip.dst
                printed = str(packet["tls"])
                if has_weak_cipher(printed):
                    weak_ciphers.add(dst)
                if has_problematic_cipher(printed):
                    problematic.add(dst)
                if has_forward_secrecy(printed):
                    forward_secret.add(dst)
    result = {}
    write = False
    if len(weak_ciphers) > 0:
        result["weak_cipher"] = list(weak_ciphers)
        print("Found weak!!")
        write = True
    if len(problematic) > 0:
        result["problem_cipher"] = list(problematic)
        print("Found problematic!!")
        write = True
    if len(forward_secret) > 0:
        result["forward_secret"] = list(forward_secret)
        print("Forward secret!!")
    if write:
        with open(result_file, "w") as ouf:
            json.dump(result, fp=ouf, sort_keys=True, indent=2)
    print("Done processing:", browser_name)

def has_weak_cipher(lines):
    for line in lines.splitlines():
        if "Cipher Suite: " in line:
            if "_RC4" in line or "_DES" in line or "_3DES" in line or "_DES" in line:
                return True
    return False

def has_problematic_cipher(lines):
    for line in lines.splitlines():
        if "Cipher Suite: " in line:
            if "_EXPORT" in line or "_NULL" in line or "_anon" in line:
                return True
    return False

def has_forward_secrecy(lines):
    for line in lines.splitlines():
        if "TLSv1.3" in line:
            return True
        if "Cipher Suite: " in line:
            if "_ECDHE" in line or "_DHE" in line:
                return True
    return False

def get_file_capture(pcap, display_filter, use_keylog_file = True):
    if use_keylog_file:
        keylog_file = "/".join(pcap.split("/")[:-3]) + "/" + SYSKEYLOG_FILE
        keylog_file = os.path.abspath(keylog_file)
    else:
        keylog_file = None
    if keylog_file and os.path.isfile(keylog_file):
        try:
            file_capture = pyshark.FileCapture(pcap,
                    display_filter=display_filter,
                    override_prefs = {
                        'tls.keylog_file': os.path.abspath(keylog_file)
                    })
        except:
            print("Error opening file capture:", pcap, display_filter)
            return None
    else:
        try:
            file_capture = pyshark.FileCapture(pcap,
                    display_filter=display_filter)
        except FileNotFoundError:
            print("Pcap not found:", pcap)
            return None
        except Exception as e:
            print("Unknown exception:", pcap, display_filter, e)
            return None
    return file_capture

def get_packets_with_filter(pcap, wireshark_filter, use_keylog_file=False):
    ret_set = defaultdict(set)
    shark_cap = get_file_capture(pcap, wireshark_filter, use_keylog_file=False)
    if shark_cap == None:
        return ret_set
    while True:
        try:
            packet = shark_cap.next()
            src = str(packet.ip.src)
            ret_set[src].add(packet)
        except AttributeError:
            print("Packet without a src ip or tcp stream? o.O")
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
        except StopIteration:
            shark_cap.close()
            break
    return dict(ret_set)

# Returns dict of sets, mapping client IP to TLS packet for each stream
# a server sends a hello in
def get_server_hello_streams(pcap):
    return get_packets_with_filter(pcap, 'tls.handshake.type == 2', use_keylog_file=False)

# Returns dict of sets, mapping client IP to TLS packet for each stream
# a client sends a hello in
def get_client_hello_streams(pcap):
    return get_packets_with_filter(pcap, 'tls.handshake.type == 1')

def get_files_from_path(path, extension):
    retset = set()
    for f in os.listdir(path):
        if f.endswith(extension):
            retset.add(path + "/" + f) # Need to track path as well
    return retset

# Check for weak cipher from a client_hello / server_hello packet
def check_weak_cipher(client_hello, server_hello, acked = False):
    if acked:
        ssl_packet = str(server_hello[0])
    else:
        ssl_packet = str(client_hello[0])

    for line in ssl_packet.splitlines():
        if "Cipher Suite: " in line:
            if "_EXPORT" in line or "_RC4" in line or "_DES" in line or "_3DES" in line:
                return 1
    return 0


# Check for forward secrecy from a from a client_hello / server_hello packet
def check_problematic_cipher(client_hello, server_hello, acked = False):
    if acked:
        ssl_packet = str(server_hello[0])
    else:
        ssl_packet = str(client_hello[0])

    for line in ssl_packet.splitlines():
        if "Cipher Suite: " in line:
            if "_NULL" in line or "_anon" in line:
                return 1
    return 0


# Check for forward secrecy from a server_hello/client_hello packet
def check_forward_secrecy(client_hello, server_hello, acked = False):
    if acked:
        # TLS v1.3 has it by default:
        if get_tls_version(None, server_hello, True) == 4:
            return 1
        ssl_packet = str(server_hello[0])
    else:
        # TLS v1.3 has it by default:
        if get_tls_version(client_hello, None, False) == 4:
            return 1
        ssl_packet = str(client_hello[0])

    for line in ssl_packet.splitlines():
        if "Cipher Suite: " in line:
            if "_ECDHE" in line or "_DHE" in line:
                return 1
    return 0


# Get TLS version from a server_hello packet
def get_tls_version(client_hello, server_hello, acked = False):
    if acked:
        ssl_packet = server_hello[0]
    else:
        ssl_packet = client_hello[0]

    # First check for TLS 1.3 support
    if acked:
        try:
            if ssl_packet.handshake_extensions_supported_version == "0x00000304":
                # TLS v1.3
                return 4
        except AttributeError:
            pass
    else:
        lines = str(ssl_packet).splitlines()
        for i in lines:
            if "Supported Version: TLS 1.3" in i:
                # TLS v1.3
                return 4

    # Otherwise check for old TLS support
    version = None
    x = str(ssl_packet.handshake_version)
    if x == "0x00000300":
        # SSL v3.0
        version = 0
    elif x == "0x00000301":
        version = 1
        # TLS v1.0
    elif x == "0x00000302":
        # TLS v1.1
        version = 2
    elif x == "0x00000303":
        # TLS v1.2
        version = 3
    return version

def main():
    # Process all .pcaps for every browser, in a parallelized way
    # Can control the amount of parallelization
    if len(sys.argv) < 2:
        print("Please provide at least 1 path to process .pcap files from.")
        return
    else:
        pcap_paths = sys.argv[1:]
        pcap_files = set()
        for path in pcap_paths:
            pcap_files.update(get_files_from_path(path + '/logs/', ".pcap"))
        processes = []
        for pcap in pcap_files:
            browser_name = pcap.split("/")[-1][:-5]
            p = multiprocessing.Process(target=generate_cipher_result, args=(pcap, browser_name))
            processes.append(p)
            p.start()
            while len(processes) >= multiprocessing.cpu_count():
                for p in processes:
                    p.join(0.1)
                    if not p.is_alive():
                        processes.remove(p)
        for p in processes:
            p.join()

# Boilerplate
if __name__ == "__main__":
    main()
