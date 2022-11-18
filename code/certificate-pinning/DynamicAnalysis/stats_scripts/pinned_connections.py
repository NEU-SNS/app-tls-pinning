import pyshark
import os
from multiprocessing import Process
import nest_asyncio
nest_asyncio.apply()
import random

data_path = "/Volumes/paracha.m/iOSDynamicTesting/common600/"
sslkeylogfile = data_path + "/sslkeylogfile.txt"
testing = "ios"

if testing == "ios":
    client_ip = "192.168"
    excluded_snis = ["apple.com", "icloud.com"]
    #excluded_snis = ["xp.apple.com", "p36-keyvalueservice.icloud.com", "guzzoni.apple.com", "itunes.apple.com", "keyvalueservice.icloud.com", "bag.itunes.apple.com", "setup.icloud.com", "gateway.icloud.com"]

elif testing == "android":
    client_ip = "10.42.0"
    excluded_snis = []

def get_pinned_connections(pcap):
    # Open pcap file with TLS connections to get handshakes information
    cap = pyshark.FileCapture(pcap, display_filter='tls and not tls.app_data', override_prefs={'tls.keylog_file': os.path.abspath(sslkeylogfile)})
    client_finished_seen = set()
    alert_seen = set()
    server_mitm_cert_seen = set()
    for packet in cap:
        streamIndex = packet['tcp'].stream

        # Sanity check that record is well formed
        try:
            assert packet['tls'].record
        except AttributeError:
            continue

        for pack in packet['tls'].record.all_fields:
            p = pack.showname_value
            if "Finished" in p and client_ip in packet['ip'].src:
                client_finished_seen.add(streamIndex)
            elif "Handshake Protocol: Certificate" in p and "id-at-commonName=mitmproxy" in str(packet['tls']):
                server_mitm_cert_seen.add(streamIndex)
            elif "Alert" in p and client_ip in packet['ip'].src:
                alert_seen.add(streamIndex)

    # (For mitmproxy version less than 7)
    # Open pcap file with HTTP connections to get MITMPROXY-emitted errors
    # cap = pyshark.FileCapture(pcap, display_filter='http.response.code == 502', override_prefs={'tls.keylog_file': './nil'})
    # mitmproxy_error_seen = set()
    # for packet in cap:
    #     streamIndex = packet['tcp'].stream
    #     if hasattr(packet.http, 'response_code') and packet.http.response_code == '502':
    #         if "Cannot establish TLS with client" in packet['http'].file_data:
    #             mitmproxy_error_seen.add(streamIndex)

    # (For mitmproxy version 7) Open pcap file with TCP FIN connections
    cap = pyshark.FileCapture(pcap, display_filter='tcp.flags.fin == 1', override_prefs={'tls.keylog_file': './nil'})
    client_tcp_fin_seen = set()
    for packet in cap:
        if client_ip in packet['ip'].src:
            client_tcp_fin_seen.add(packet['tcp'].stream)

    # Filter out TLS connections which were pinning
    pinnedSNIs = set()
    cap = pyshark.FileCapture(pcap, display_filter='tls.handshake.type == 1', override_prefs={'tls.keylog_file': './nil'})
    for packet in cap:
        streamIndex = packet['tcp'].stream
        # IF CERTIFICATE SEEN + CLIENT-FINISHED NOT SEEN + ALERT SEEN (Android+iOS) or CLIENT TCP FINISHED SEEN (iOS)
        if streamIndex in server_mitm_cert_seen and (streamIndex not in client_finished_seen):
            if testing == "android":
                if streamIndex in alert_seen:
                    try:
                        pinnedSNIs.add(packet['tls'].handshake_extensions_server_name)
                    except AttributeError:
                        pinnedSNIs.add("without-SNI: " + str(packet['ip'].dst))
            elif testing == "ios":
                if streamIndex in alert_seen or streamIndex in client_tcp_fin_seen:
                    pinnedSNIs.add(packet['tls'].handshake_extensions_server_name)
                    try:
                        pinnedSNIs.add(packet['tls'].handshake_extensions_server_name)
                    except AttributeError:
                        pinnedSNIs.add("without-SNI: " + str(packet['ip'].dst))

    removalSNIs = set()
    for x in excluded_snis:
        for sni in pinnedSNIs:
            if x in sni:
                removalSNIs.add(sni)
    pinnedSNIs = pinnedSNIs.difference(removalSNIs)

    print(pcap, len(pinnedSNIs), pinnedSNIs)


if __name__ == '__main__':
    pcaps = [os.path.join(dp, f) for dp, dn, filenames in os.walk(data_path) for f in filenames if os.path.splitext(f)[1] == '.pcap']
    random.shuffle(pcaps)
    processes = []
    for pcap in pcaps:
        p = Process(target=get_pinned_connections, args=(pcap, ))
        processes.append(p)
        p.start()
        while len(processes) >= 2:
            for p in processes:
                p.join(0.1)
                if not p.is_alive():
                    processes.remove(p)
    for p in processes:
        p.join()
