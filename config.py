from scapy.all import get_if_hwaddr, get_if_list


def get_default_interface():
    # Get a list of network interfaces
    interfaces = get_if_list()

    # Iterate over the interfaces
    for i in interfaces:
        try:
            # Get the MAC address of the interface
            mac = get_if_hwaddr(i)

            # return if the MAC address matches that of M3's enp0s3 interface
            if mac == "08:00:27:d0:25:4b":  
                return i
        except:
            pass
    print("Could not determine default network interface")
    sys.exit(1)

def get_network_config():
    interface = get_default_interface()
    return interface

