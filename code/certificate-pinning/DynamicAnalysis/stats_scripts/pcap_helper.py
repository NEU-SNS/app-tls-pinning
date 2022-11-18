# Process all .pcaps for a particular device for TLS analysis
def process_pcap(pcap, browser_name):
    out_dir = "/".join(pcap.split("/")[:-1])
    test_type = None
    result_file = out_dir + "/" + browser_name + ".result"
    if os.path.exists(out_dir + "../android"):
        test_type = ANDROID_TEST_TYPE
    elif os.path.exists(out_dir + "../ios"):
        test_type = IOS_TEST_TYPE
    else:
        print("Set android or ios in the result base dir, crashing...")
        return

    if os.path.exists(result_file):
        print("Found result for:", browser_name, "skipping...")
        return

    package_name = browser_name.split("-")[0]
    package_hash = browser_name.split("-")[1].split(".")[0]
    print("Processing", pcap)

    # Get info from pcap required to tell if a handshake passed or failed
    client_hellos = get_client_hello_streams(pcap)
    client_finisheds = get_client_finished_streams(pcap)
    client_alerts = get_client_alert_streams(pcap)
    server_mitm_certs = get_server_cert_streams(pcap)
    if test_type == IOS_TEST_TYPE:
        #mitmproxy_errors = get_mitmproxy_error_streams(pcap)
        client_tcp_fins = get_client_tcp_fin_streams(pcap)
    # Debug prints
    # print("Hellos", client_hellos)
    # print("Finished", client_finisheds)
    # print("Alerts", client_alerts)
    failed_handshakes = defaultdict(set)
    successful_handshakes = defaultdict(set)
    quic = set()
    # Logic to find failed handshakes and successful handshakes
    for client, hello_packets in client_hellos.items():
        if CLIENT_SUBNET_PREFIX_1 not in client and \
                CLIENT_SUBNET_PREFIX_2 not in client:
            continue
        # For every client hello in pcap
        for hello_packet in hello_packets:
            if hasattr(hello_packet, 'tcp'):
                stream = int(hello_packet.tcp.stream)
            elif hasattr(hello_packet, 'quic'):
                # Mitmproxy cannot handle quic, so we can't really MITM it for
                # now, log and continue
                # print("Quic:", package_name)
                quic.add(hello_packet.quic.tls_handshake_extensions_server_name)
                continue
            # Was the stream mitmed?
            mitmed = stream_in_some_entry(stream, server_mitm_certs)
            # Have we seen a client finish for the stream?
            client_finish = client in client_finisheds and \
                    stream in client_finisheds[client]
            # Have we seen a client alert for the stream?
            client_alert = client in client_alerts and \
                    stream in client_alerts[client]
            # This is an alternate to alert for IOS tests
            # Will always be False for android tests, so logic later is same
            #mitmproxy_error_seen = test_type == IOS_TEST_TYPE and \
            #        stream_in_some_entry(stream, mitmproxy_errors)
            # For latest mitmproxy version (7 onwards) we use client_tcp_fin_seen instead of mitmproxy_error_seen
            client_tcp_fin_seen = test_type == IOS_TEST_TYPE and \
                                  client in client_tcp_fins and stream in client_tcp_fins[client]
            if hasattr(hello_packet.tls, 'handshake_extensions_server_name'):
                server_name = hello_packet.tls.handshake_extensions_server_name
            else:
                # print("No SNI:", hello_packet)
                server_name = hello_packet.ip.dst
            if mitmed and (not client_finish) and \
                    (client_alert or client_tcp_fin_seen):
                failed_handshakes[client].add(server_name)
            elif mitmed and client_finish:
                successful_handshakes[client].add(server_name)
            elif mitmed and (not client_finish) and (not client_alert):
                print("Mitmed, not finished, but also no alert!", stream)
            else:
                print("Non mitm server cert served?", pcap, stream)
    # Clean results
    failed_handshakes = clean_result(failed_handshakes, test_type)
    # Write results to out_dir
    result = {
        "app_hash": package_hash,
        "package_name": package_name
    }
    if len(failed_handshakes) > 0:
        result["failed_handshakes"] = make_lists(failed_handshakes)
    if len(successful_handshakes) > 0:
        result["successful_handshakes"] = make_lists(successful_handshakes)
    if len(quic) > 0:
        result["quic"] = list(quic)
    with open(result_file, "w") as ouf:
        json.dump(result, fp=ouf, sort_keys=True, indent=2)

def make_lists(dict_of_something):
    ret_dict = {}
    for k, v in dict_of_something.items():
        ret_dict[k] = list(v)
    return ret_dict

def clean_result(result, test):
    ret_dict = defaultdict(set)
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
                ret_dict[k].add(sni)
    return ret_dict

def stream_in_some_entry(stream, dict_of_something):
    for k, v in dict_of_something.items():
        if stream in v:
            return True
    return False

# Key log not required
# Returns dict of sets, mapping client IP to TLS stream number for each stream
# a client sends a hello in
def get_client_hello_streams(pcap):
    ret_set = defaultdict(set)

    shark_cap = get_file_capture(pcap, 'tls.handshake.type == 1', use_keylog_file=False)
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

def get_client_finished_streams(pcap):
    ret_set = defaultdict(set)

    shark_cap = get_file_capture(pcap, 'tls.handshake.type == 20')
    if shark_cap == None:
        return ret_set

    while True:
        try:
            merged_packet = shark_cap.next()
            src = str(merged_packet.ip.src)
            stream = int(merged_packet.tcp.stream)
            for packet in merged_packet.tls.record.all_fields:
                # Unfortunately, this is the only way to get info from records,
                # there are no easy variables set for multi record packets
                if packet.showname_value == "Handshake Protocol: Finished":
                    ret_set[src].add(stream)
        except AttributeError:
            print("How do we have a bad attribute o.O")
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
        except StopIteration:
            shark_cap.close()
            break
    return dict(ret_set)

# Needs keylog_file to handle encrypted alerts
def get_client_alert_streams(pcap):
    ret_set = defaultdict(set)

    shark_cap = get_file_capture(pcap, 'tls.record.content_type == 21')
    if shark_cap == None:
        return ret_set


    while True:
        try:
            packet = shark_cap.next()
            src = str(packet.ip.src)
            stream = int(packet.tcp.stream)
            ret_set[src].add(stream)
        except AttributeError:
            print("How do we have a bad attribute o.O")
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
        except StopIteration:
            shark_cap.close()
            break
    return dict(ret_set)

def get_server_cert_streams(pcap):
    ret_set = defaultdict(set)

    shark_cap = get_file_capture(pcap, 'tls.handshake.type == 11')
    if shark_cap == None:
        return ret_set

    while True:
        try:
            merged_packet = shark_cap.next()
            src = str(merged_packet.ip.src)
            stream = int(merged_packet.tcp.stream)
            if "id-at-commonName=mitmproxy" not in str(merged_packet.tls):
                continue
            for packet in merged_packet.tls.record.all_fields:
            # Unfortunately, this is the only way to get info from records,
            # there are no easy variables set for multi record packets
                if packet.showname_value == "Handshake Protocol: Certificate":
                    ret_set[src].add(stream)
        except AttributeError:
            print("Record without a showname_value? o.O")
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
        except StopIteration:
            shark_cap.close()
            break
    return dict(ret_set)


def get_client_tcp_fin_streams(pcap):
    ret_set = defaultdict(set)

    shark_cap = get_file_capture(pcap, 'tcp.flags.fin == 1', use_keylog_file=False)
    if shark_cap == None:
        return ret_set

    while True:
        try:
            packet = shark_cap.next()
            src = str(packet.ip.src)
            stream = int(packet.tcp.stream)
            ret_set[src].add(stream)
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
        except StopIteration:
            shark_cap.close()
            break
    return dict(ret_set)

def get_mitmproxy_error_streams(pcap):
    ret_set = defaultdict(set)

    shark_cap = get_file_capture(pcap, 'http.response.code == 502', use_keylog_file=False)
    if shark_cap == None:
        return ret_set

    while True:
        try:
            packet = shark_cap.next()
            src = str(packet.ip.src)
            stream = int(packet.tcp.stream)
            if "Cannot establish TLS with client" in packet.http.file_data:
                ret_set[src].add(stream)
        except AttributeError:
            print("Record without a showname_value? o.O")
        except lxml.etree.XMLSyntaxError:
            print("Bad line in parsing pcap?")
        except StopIteration:
            shark_cap.close()
            break
    return dict(ret_set)
