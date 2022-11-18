import pyshark
import os
from multiprocessing import Process
import nest_asyncio
nest_asyncio.apply()
import random

data_path = "/net/data/cert-pinning/ios/dynamic_results30seconds_newdevice/iOSDynamicTestingNewDevice/Common600/"

def get_sni_ip(pcap):
    cap = pyshark.FileCapture(pcap, display_filter='tls.handshake.type == 1', override_prefs={'tls.keylog_file': './nil'})
    snis = {}
    for packet in cap:
        try:
            name = packet['tls'].handshake_extensions_server_name
        except AttributeError:
            name = "without-SNI: " + str(packet['ip'].dst)

        if name not in snis:
            snis[name] = str(packet['ip'].dst)
    for sni in snis:
        print(pcap, sni, snis[sni])

if __name__ == '__main__':
    pcaps = [os.path.join(dp, f) for dp, dn, filenames in os.walk(data_path) for f in filenames if os.path.splitext(f)[1] == '.pcap']
    random.shuffle(pcaps)
    processes = []
    for pcap in pcaps:
        p = Process(target=get_sni_ip, args=(pcap, ))
        processes.append(p)
        p.start()
        while len(processes) >= 72:
            for p in processes:
                p.join(0.1)
                if not p.is_alive():
                    processes.remove(p)
    for p in processes:
        p.join()