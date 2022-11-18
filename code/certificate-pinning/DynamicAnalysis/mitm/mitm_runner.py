import asyncio
import threading
import logging

import mitmproxy.log
import mitmproxy.proxy.protocol
from mitmproxy.options import Options
from mitmproxy.proxy.config import ProxyConfig
from mitmproxy.proxy.server import ProxyServer
from mitmproxy.tools.dump import DumpMaster

'''
Pre-requisites:

1) pip install mitmproxy (https://pypi.org/project/mitmproxy) (preferably in a venv)
2) Add two manual comments in mitmproxy/proxy/protocol/tls.py

        After line: 395: 
        self.log("manual_proxy_tester: Successful in establishing TLS with client, name: {}".format(cert.cn), "debug")
        
        After line: 397: 
        self.log("manual_proxy_tester: ClientHandshakeException in establishing TLS with client , name: {}".format(cert.cn), "debug")
        
        Example code snippet after putting the logs: 
                self.client_conn.rfile.peek(1)
                self.log("manual_proxy_tester: Successful in establishing TLS with client, name: {}".format(cert.cn), "debug")
                except exceptions.TlsException as e:
                sni_str = self._client_hello.sni and self._client_hello.sni.decode("idna")
                self.log("manual_proxy_tester: ClientHandshakeException in establishing TLS with client , name: {}".format(cert.cn),
                         "debug")
                raise exceptions.ClientHandshakeException(
                    "Cannot establish TLS with client (sni: {sni}): {e}".format(
                        sni=sni_str, e=repr(e)
                    ),
                    sni_str or repr(self.server_conn.address)
                )
3) Set manual proxy with host (device running this script) and port (8080) in your rooted device / emulator
'''

'''
-- https://github.com/mitmproxy/mitmproxy/issues/1846

The problem is as follows: When mitmproxy connects upstream, 
it verifies the certificate the server presents. One part 
of the verification is to check if the certificate matches 
the hostname the client is expecting. Modern versions of TLS mandate 
the client to send a Server Name Indication (SNI) extension during 
the TLS handshake which names the expected site. However, if 
your client does not send a SNI extension, there's no way for 
us to verify the authenticity of the server's certificate as 
we don't know which site the client is expecting and we fail 
the connection in the way you described. You can work around 
this by disabling certificate verification with mitmproxy 
--insecure - be warned that you are subject to man-in-the-middle attacks then.
'''

logging.basicConfig(filename='mitm.log', format='%(levelname)s - %(message)s')


class Addon(object):
    def __init__(self):
        self.num = 1

    def log(self, entry: mitmproxy.log.LogEntry):
        if 'manual_proxy_tester' in entry.msg:
            print(entry)
            if 'Successful' in entry.msg:
                logging.debug(entry.msg)
            else:
                logging.warning(entry.msg)

    def clientdisconnect(self, layer: mitmproxy.proxy.protocol.Layer):
        """
            A client has disconnected from mitmproxy.
        """
        print("Client disconnect alert!")


def loop_in_thread(loop, m):
    asyncio.set_event_loop(loop)
    m.run_loop(loop.run_forever)


if __name__ == "__main__":
    options = Options(listen_host='0.0.0.0', listen_port=8080, http2=True, ssl_insecure=True)
    m = DumpMaster(options, with_termlog=False, with_dumper=False)
    config = ProxyConfig(options)
    m.server = ProxyServer(config)
    m.addons.add(Addon())

    loop = asyncio.get_event_loop()
    t = threading.Thread( target=loop_in_thread, args=(loop,m) )
    t.start()
