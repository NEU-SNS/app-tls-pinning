import pyshark
import os
from multiprocessing import Process
import nest_asyncio
nest_asyncio.apply()
import random

data_path = "/net/data/cert-pinning/ios/dynamic_results30seconds/iOSDynamicTesting/common600-withoutMITM/"
sslkeylogfile = data_path + "/sslkeylogfile.txt"
testing = "ios"
output = "success"

if testing == "ios":
    client_ip = "192.168"
    excluded_snis = ["apple.com", "icloud.com", "mzstatic.com"]

elif testing == "android":
    client_ip = "10.42"
    excluded_snis = []


def get_pinned_connections(pcap):
    # Open pcap file with TLS connections to see which connections have "Application Data"
    cap = pyshark.FileCapture(pcap, display_filter='tls', override_prefs={'tls.keylog_file': './nil'})
    application_data_seen = {}
    server_hello_seen = set()
    for packet in cap:
        streamIndex = packet['tcp'].stream

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

    # Open pcap file with TCP FIN/RST connections
    cap = pyshark.FileCapture(pcap, display_filter='tcp.flags.fin == 1 or tcp.flags.reset == 1', override_prefs={'tls.keylog_file': './nil'})
    client_closed_seen = set()
    for packet in cap:
        if client_ip in packet['ip'].src:
            client_closed_seen.add(packet['tcp'].stream)

    # Filter out TLS destinations that were "used" in any TLS connection (i.e., sent Application Data)
    usedConns = set()
    destinationsSeen = set()
    cap = pyshark.FileCapture(pcap, display_filter='tls.handshake.type == 1', override_prefs={'tls.keylog_file': './nil'})
    for packet in cap:
        streamIndex = packet['tcp'].stream
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

    # Filter out TLS destinations which failed
    failedConns = set()
    cap = pyshark.FileCapture(pcap, display_filter='tls.handshake.type == 1', override_prefs={'tls.keylog_file': './nil'})
    for packet in cap:
        streamIndex = packet['tcp'].stream

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

    print(pcap, ';'.join(usedConns), ';'.join(failedConns), sep='|')

if __name__ == '__main__':
    pcaps = [os.path.join(dp, f) for dp, dn, filenames in os.walk(data_path) for f in filenames if os.path.splitext(f)[1] == '.pcap']
    random.shuffle(pcaps)
    processes = []
    for pcap in pcaps:
        p = Process(target=get_pinned_connections, args=(pcap, ))
        processes.append(p)
        p.start()
        while len(processes) >= 72:
            for p in processes:
                p.join(0.1)
                if not p.is_alive():
                    processes.remove(p)
    for p in processes:
        p.join()
