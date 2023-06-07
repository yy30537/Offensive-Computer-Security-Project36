#scan the local network for devices and gateways

from scapy.all import ARP, Ether, srp
import scapy.all as scapy
import netifaces as ni

interface = 'enp0s8'
def list_interfaces():
    interfaces = ni.interfaces()
    return interfaces
def get_own_ip_mac_adress(interface):
    ni.ifaddresses(interface)
    ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    mac = ni.ifaddresses(interface)[ni.AF_LINK][0]['addr']
    result = {'ipAttacker': ip, 'macAttacker': mac}
    return result

def get_gateway():
    gateway = ni.gateways()['default'][ni.AF_INET][0]
    return gateway

def scan_network(interface, interval=[1,24]):
    ip = get_own_ip_mac_adress(interface)['ipAttacker']
    ip = ip.split('.')
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    devices_list = []
    for i in range(interval[0], interval[1]):
        target_ip = ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + str(i)
        arp = ARP(pdst=target_ip)
        packet = broadcast/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            if (received.haslayer(ARP)):
                device = {'ip': received[ARP].psrc, 'mac': received[ARP].hwsrc}
                devices_list.append(device)
                print(device)
    return devices_list
