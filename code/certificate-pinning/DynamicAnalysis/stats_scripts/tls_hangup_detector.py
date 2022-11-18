#!/usr/bin/env python3
import pyshark
import os
import pickle
import random
import sys
import multiprocessing
from os import path
import json
from collections import defaultdict
import lxml

# Need to change this based on what client IPs we expect
CLIENT_SUBNET_PREFIX_1 = "10.42.0"
CLIENT_SUBNET_PREFIX_2 = "192.168.2"

# Test Types
ANDROID_TEST_TYPE = 0
IOS_TEST_TYPE = 1

# Background traffic that is detected as app pinning which we manually clean
APPLE_ALLOWED_PINNING = [
    "apple.com",
    "icloud.com",
    "mzstatic.com"
]
ANDROID_ALLOWED_PINNING = []

SYSKEYLOG_FILE = "sslkeylogfile.txt"

RESULT_EXTN = ".result"

associated_domains_ios = {}
with open("all-associated-domains.txt") as aF:
    for l in aF.readlines():
        items = l.strip().split(";")
        name = items[0]
        doms = items[1:]
        if len(doms) > 0:
            associated_domains_ios[name] = set(doms)


def domain_belongs_to_associated(domain, associated_doms):
    if domain.strip() == "":
        return False

    belongs = False
    for ad in associated_doms:
        if "*." not in ad:
            if ad == domain:
                belongs = True
                break

        # Wildcard check
        else:
            if ad.split(".", 1)[1] == domain.split(".", 1)[1]:
                belongs = True
                break

            if ad.replace("*.", "") == domain:
                belongs = True
                break

    return belongs



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
        # browser_name = "-".join(browser_name.split("-")[:2])
        p = multiprocessing.Process(target=process_pcap, args=(pcap, browser_name))
        processes.append(p)
        p.start()
        cores = multiprocessing.cpu_count()
        while len(processes) >= cores:
            for p in processes:
                p.join(0.1)
                if not p.is_alive():
                    processes.remove(p)
    for p in processes:
        p.join()

# Process all .pcaps for a particular device for TLS analysis
def process_pcap(pcap, browser_name):
    out_dir = "/".join(pcap.split("/")[:-1])
    test_type = None
    result_file = out_dir + "/" + browser_name + ".result"
    package_name = browser_name.rsplit("-", 1)[0]
    package_hash = browser_name.rsplit("-", 1)[1]
    if os.path.exists(out_dir + "../android"):
        # Line left for legacy, might be used if code is refactored
        test_type = ANDROID_TEST_TYPE
        client_ip = CLIENT_SUBNET_PREFIX_1
        excluded_snis = ANDROID_ALLOWED_PINNING
    elif os.path.exists(out_dir + "../ios"):
        test_type = IOS_TEST_TYPE
        client_ip = CLIENT_SUBNET_PREFIX_2
        excluded_snis = APPLE_ALLOWED_PINNING
    else:
        print("Set android or ios in the result base dir, crashing...")
        return

    cap = pyshark.FileCapture(pcap, display_filter='tls', override_prefs={'tls.keylog_file': './nil'})
    application_data_seen = {}
    server_hello_seen = set()
    while True:
        try:
            packet = cap.next()
            try:
                streamIndex = packet['tcp'].stream
            except KeyError:
                continue
            # Sanity check that record is well formed
            try:
                assert packet['tls'].record
            except AttributeError:
                continue

            indices_interest = []
            index = 0
            otherTLS = True
            for pack in packet['tls'].record.all_fields:
                p = str(pack.showname)

                if "Server Hello" in p and client_ip not in packet['ip'].src:
                    server_hello_seen.add(streamIndex)

                elif "Application Data Protocol" in p and client_ip in packet['ip'].src:
                    indices_interest.append(index)

                    if "TLSv1.3" in p:
                        otherTLS = False

                index += 1

            application_data_lengths = []
            for x in indices_interest:
                application_data_lengths.append(int(packet['tls'].record_length.all_fields[x].showname_value))

            if len(application_data_lengths) > 0:
                if streamIndex not in application_data_seen:
                    application_data_seen[streamIndex] = (application_data_lengths, otherTLS)
                else:
                    application_data_seen[streamIndex] = (application_data_seen[streamIndex][0] + application_data_lengths, otherTLS)
        except AttributeError:
            print("How do we have a bad attribute o.O")
            cap.close()
            break
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
            cap.close()
            break
        except StopIteration:
            cap.close()
            break
    # Open pcap file with TCP FIN/RST connections
    cap = pyshark.FileCapture(pcap, display_filter='tcp.flags.fin == 1 or tcp.flags.reset == 1', override_prefs={'tls.keylog_file': './nil'})
    client_closed_seen = set()
    while True:
        try:
            packet = cap.next()
            if client_ip in packet['ip'].src:
                client_closed_seen.add(packet['tcp'].stream)
        except AttributeError:
            print("How do we have a bad attribute o.O")
            cap.close()
            break
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
            cap.close()
            break
        except StopIteration:
            cap.close()
            break
    # Filter out TLS destinations that were "used" in any TLS connection (i.e., sent Application Data)
    usedConns = set()
    destinationsSeen = set()
    cap = pyshark.FileCapture(pcap, display_filter='tls.handshake.type == 1', override_prefs={'tls.keylog_file': './nil'})
    while True:
        try:
            packet = cap.next()
            try:
                streamIndex = packet['tcp'].stream
            except KeyError:
                continue
            used = False

            # We do not consider connections where Server Hello was not seen
            if streamIndex not in server_hello_seen:
                continue

            try:
                name = packet['tls'].handshake_extensions_server_name
            except AttributeError:
                name = "without-SNI: " + str(packet['ip'].dst)
            destinationsSeen.add(name)

            # We will mark a connection as "used" IF
            # Any "Application Data" seen in TLSv1.2 / below
            #                   OR IF
            # Specific number and length "Application Data" seen in TLSv1.3
            if streamIndex in application_data_seen and streamIndex in server_hello_seen:
                # For TLSv1.2 or below
                if application_data_seen[streamIndex][1]:
                    if len(application_data_seen[streamIndex][0]) > 0:
                        used = True

                # For TLSv1.3
                else:
                    if len(application_data_seen[streamIndex][0]) > 2:
                        used = True
                    elif len(application_data_seen[streamIndex][0]) == 2:
                        if application_data_seen[streamIndex][0][1] != 19:
                            used = True

            if used:
                usedConns.add(name)
        except AttributeError:
            print("How do we have a bad attribute o.O")
            cap.close()
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
            cap.close()
        except StopIteration:
            cap.close()
            break
    # Filter out TLS destinations which failed
    failedConns = set()
    cap = pyshark.FileCapture(pcap, display_filter='tls.handshake.type == 1', override_prefs={'tls.keylog_file': './nil'})
    while True:
        try:
            packet = cap.next()
            try:
                streamIndex = packet['tcp'].stream
            except KeyError:
                continue

            # We do not consider connections where Server Hello was not seen
            if streamIndex not in server_hello_seen:
                continue

            try:
                name = packet['tls'].handshake_extensions_server_name
            except AttributeError:
                name = "without-SNI: " + str(packet['ip'].dst)

            # A TLS destination is failed if
            # 1) It was never used
            # 2) The client closed it down by sending TCP FIN or TCP RST
            if name not in usedConns and streamIndex in client_closed_seen:
                failedConns.add(name)
        except AttributeError:
            print("How do we have a bad attribute o.O")
            cap.close()
            break
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
            cap.close()
            break
        except StopIteration:
            cap.close()
            break
    # Filter destinations marked as background traffic
    removalSNIs = set()
    for x in excluded_snis:
        for sni in usedConns:
            if x in sni:
                removalSNIs.add(sni)
    usedConns = usedConns.difference(removalSNIs)

    removalSNIs = set()
    for x in excluded_snis:
        for sni in failedConns:
            if x in sni:
                removalSNIs.add(sni)
    failedConns = failedConns.difference(removalSNIs)

    # Filter destinations marked as associated domains for ios
    if test_type == IOS_TEST_TYPE:
        usedConnsFiltered = set()
        failedConnsFiltered = set()

        for used in usedConns:
            if not domain_belongs_to_associated(used, associated_domains_ios[package_hash]):
                usedConnsFiltered.add(used)

        for failed in failedConns:
            if not domain_belongs_to_associated(failed, associated_domains_ios[package_hash]):
                failedConnsFiltered.add(failed)

        usedConns = usedConnsFiltered
        failedConns = failedConnsFiltered

    # print("######################")
    print(usedConns)
    # print("######################")
    print(failedConns)
    result = {
        "app_hash": package_hash,
        "package_name": package_name
    }
    if len(usedConns) > 0:
        result["successful_handshakes"] = {"client_ip": list(usedConns)}
    if len(failedConns) > 0:
        result["failed_handshakes"] = {"client_ip": list(failedConns)}
    with open(result_file, "w") as ouf:
        json.dump(result, fp=ouf, sort_keys=True, indent=2)
    print("Done processing:", browser_name)

def clean_result(result, test):
    ret_dict = defaultdict(list)
    if test == ANDROID_TEST_TYPE:
        allowed = ANDROID_ALLOWED_PINNING
    elif test == IOS_TEST_TYPE:
        allowed = APPLE_ALLOWED_PINNING
    for k, v in result.items():
        for sni in v:
            add_entry = True
            for a in allowed:
                if a in sni:
                    add_entry = False
                    break
            if add_entry:
                ret_dict[k].append(sni)
    return ret_dict

def break_app_data(app_data_packets):
    # Tuples of original and app_data part
    ret_lst = []
    for possibly_merged_packet in app_data_packets:
        index = 0
        for broken_packet in possibly_merged_packet['tls'].record.all_fields:
            if "Application Data Protocol" in str(broken_packet.showname):
                ret_lst.append((index, possibly_merged_packet))
            index += 1
    return ret_lst

def get_sni(packet):
    if hasattr(packet.tls, 'handshake_extensions_server_name'):
        return packet.tls.handshake_extensions_server_name
    else:
        return packet.ip.src

def get_stream_index(packet):
    if hasattr(packet, 'tcp') and hasattr(packet['tcp'], 'stream'):
        return packet['tcp'].stream
    return None

def get_indices(packets):
    indices = set()
    for packet in packets:
        if hasattr(packet, 'tcp') and hasattr(packet['tcp'], 'stream'):
                indices.add(packet['tcp'].stream)
    return indices


def get_app_data_for_stream_and_ip(stream_index, client_ip, application_datas):
    ret_lst = []
    if client_ip not in application_datas:
        return ret_lst
    for packet in application_datas[client_ip]:
        if hasattr(packet, 'tcp') and hasattr(packet['tcp'], 'stream'):
                this_stream_index = packet['tcp'].stream
        else:
            continue
        if this_stream_index == stream_index:
            ret_lst.append(packet)
    return ret_lst

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

# # Returns dict of sets, mapping client IP to TLS packet for each stream
# a client sends a hello in
def get_application_data_streams(pcap):
    return get_packets_with_filter(pcap, 'tls.app_data')

# Returns dict of sets, mapping client IP to TLS packet for each stream
# that is a FIN or RESET
def get_fins_and_resets(pcap):
    return get_packets_with_filter(pcap, 'tcp.flags.fin == 1 or tcp.flags.reset == 1')

def get_files_from_path(path, extension):
    retset = set()
    for f in os.listdir(path):
        if f.endswith(extension):
            retset.add(path + "/" + f) # Need to track path as well
    return retset

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
        except:
            print("Unknown exception:", pcap, display_filter)
            return None
    return file_capture


if __name__ == "__main__":
    main()
