from netfilterqueue import NetfilterQueue
from scapy.all import IP

def process_packet(packet):
    # Convert packet to a Scapy packet
    scapy_packet = IP(packet.get_payload())
    
    # Print packet
    print(scapy_packet.summary())
    
    # Accept packet
    packet.accept()

def ssl_strip():
    # Create and bind to NetfilterQueue
    queue = NetfilterQueue()
    queue.bind(0, process_packet)

    try:
        print("[+] Starting packet interception...")
        queue.run()
    except KeyboardInterrupt:
        print("\n[-] Stopping packet interception...")
        queue.unbind()

if __name__ == "__main__":
    ssl_strip()

'''
todo:
now the ssl_strip.py is not working, it is not able to redirect the traffic to port 10000
'''