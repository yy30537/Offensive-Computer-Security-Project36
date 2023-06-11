from scapy.all import * 
import os
from netfilterqueue import NetfilterQueue

def process_packet(packet):
    print("[+] Packet intercepted...")

    
    # Accept packet
    packet.accept()


def ssl_strip():
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
    ssl_strip()

