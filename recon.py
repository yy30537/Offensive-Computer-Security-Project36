#scan the local network for devices and gateways

from scapy.all import ARP, Ether, srp, sniff
import scapy.all as scapy
import netifaces as ni
import csv

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
    gateway_ip = ni.gateways()['default'][ni.AF_INET][0]
    ARP_request = ARP(pdst=gateway_ip)
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = broadcast/ARP_request
    result = srp(packet, timeout=3, verbose=0)[0]
    gateway_mac = result[0][1].hwsrc
    result = {'ipGateway': gateway_ip, 'macGateway': gateway_mac}
    return result

def scan_network(interface, interval=[1,10]):
    ip = get_own_ip_mac_adress(interface)['ipAttacker']
    ip = ip.split('.')
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    devices_list = []
    for i in range(interval[0], interval[1]):
        if interface == 'enp0s3':
            target_ip = ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + '10' + str(i)
        elif interface == 'enp0s8':
            target_ip = ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + str(i)
        else:
            print('Not Implemented Yet... :(')
        arp = ARP(pdst=target_ip)
        packet = broadcast/arp
        result = srp(packet, timeout=1, verbose=0, iface=interface)[0]
        for sent, received in result:
            if (received.haslayer(ARP)):
                device = {'ip': received[ARP].psrc, 'mac': received[ARP].hwsrc}
                devices_list.append(device)
        #store in csv file
        #overwrite file
        file = open("scan_active.csv", "w")
        for device in devices_list:
            file.write(device['ip'] + "," + device['mac'] + "\n")
        file.close()
    return devices_list

def csv_to_dict(file_name):
    with open(file_name, mode='r') as infile:
        reader = csv.reader(infile)
        mydict = {}
        for rows in reader:
            mydict[rows[0]] = rows[1]
    return mydict

def dictionary_to_csv(file_path, dictionary):
    with open(file_path, 'wb') as csvfile:
        writer = csv.writer(csvfile)
        for key, value in dictionary.items():
            writer.writerow([key, value])


def passive_scan_network(interface):
    file_name = "passive_scan.csv"
    try:
        file = open(file_name, "r")
        file.close()
    except:
        print("file not found, creating file")
        file = open(file_name, "w")
        file.close()
    net_dict = csv_to_dict(file_name)
    print("passive scan")
    print("listening")
    pkg_arp = sniff(filter="arp", count=1, iface=interface)
    ipSource = pkg_arp[0][ARP].psrc
    macSource = pkg_arp[0][ARP].hwsrc
    if pkg_arp[0][ARP].op == 2:
        print("ARP Reply")
    elif pkg_arp[0][ARP].op == 1:
        print("ARP Request") 
    net_dict[ipSource] = macSource 
    print(net_dict)
    dictionary_to_csv(file_name, net_dict)


#check if file exists

#while True:
    #passive_scan_network(interface)

scan_network(interface)

    

