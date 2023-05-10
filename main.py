import config
import arp_poison
import dns_spoof
#import ssl_strip
import sys

# accepts a command-line argument to determine whether to run 
# ARP poisoning, DNS spoofing, or SSL stripping. 
# imports and uses the modules and functions based on command-line argument.
def main():

    # get default network interface
    interface = config.get_network_config()

    # print configs
    print("Interface: {}".format(interface))
    print("Target IP (M1): 192.168.56.101")
    print("Gateway IP (M2): 192.168.56.102")
    print("Attacker IP (M3): 192.168.56.103")

    
    if len(sys.argv) != 2:
        print("Usage: python main.py [arp|dns|ssl]")
        sys.exit(1)

    if sys.argv[1] == "arp":
        arp_poison.arp_poison("192.168.56.101", "192.168.56.102", interface)
    elif sys.argv[1] == "dns":
        dns_spoof.start_spoof(interface)
    #elif sys.argv[1] == "ssl":
        #ssl_strip.start_strip(interface)
    else:
        print("Unknown command: {}. Use either 'arp', 'dns', or 'ssl'".format(sys.argv[1]))
        sys.exit(1)

if __name__ == "__main__":
    main()
