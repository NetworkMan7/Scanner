import nmap
scanner = nmap.Port.Scanner()
snet = netstat.network.scanner()
print("Welcome to my MrHook tool")
print(""" <......This scanner is developed by MRX........> """)
choice = input("Please enter your option")
print("Your selected option is: ",choice )
type(choice)
tool = input("""\n please enter the option tools 
                                                1)nmap
                                                2)Recon -ng \n""")
print("You have selected option: ",tool)                                           
if tool =='1':
    print("you choice Nmap",ip_addr)
elif tool =='2':
    print("You choose Metaspolit",payload)
elif tool>='3': 
    print("please enter a valid option")
#Netstat
mac_addr =input("Please Enter Target Ip Adress or Mac Adress")
print("The target Ip adress or Macadress is: ",snet)
type(mac_addr)
snet = input("""\n please enter the type of scan to run 
                                                1)Listen port and creating connection scan
                                                2)Ethernet scan
                                                3)Domain scan 
                                                4)ID scan     
                                                5)Route scan
                                                6)IP packet   \n""")
print("You have selected option: ",snet)
if resp == '1':
    print("Netstat version: ",Netstat.netstat_version())
    snet.scan(mac_addr,  '-a -b')
    print(snet.scaninfo())
    print("Ip Status: ", Scanner[mac_addr].state())
    print(scanner [mac_addr].all_protocols())
    print("open ports: ", Scannner[mac_addr]['listen'].keys())
elif resp == '2':
        print("Netstat version: ",Netstat.netstat_version())
        snet.scan(mac_addr, '-e')
        print(snet.scaninfo())
        print("Ip Status: ", Scanner[mac_addr].state())
        print(scanner [mac_addr].all_protocols())
        print("open ports: ", Scannner[mac_addr]['Ethernet'].keys())
elif resp == '3':
        print("Netstat version: ",Netstat.netstat_version())
        snet.scan.scan(mac_addr, '-f')
        print(snet.scaninfo())
        print("Ip Status: ", Scanner[mac_addr].state())
        print(scanner [mac_addr].all_protocols())
        print("open ports: ", Scannner[mac_addr]['Domain'].keys())
elif resp == '4':
        print("Netstat version: ",Netstat.netstat_version())
        snet.scan.scan(mac_addr, '-o')
        print(snet.scaninfo())
        print("Ip Status: ", Scanner[mac_addr].state())
        print(scanner [mac_addr].all_protocols())
        print("open ports: ", Scannner[mac_addr]['ID'].keys())
elif resp == '5':
        print("Netstat version: ",Netstat.netstat_version())
        snet.scan.scan(mac_addr, '-r')
        print(snet.scaninfo())
        print("Ip Status: ", Scanner[mac_addr].state())
        print(scanner [mac_addr].all_protocols())
        print("open ports: ", Scannner[mac_addr]['Route'].keys())
elif resp == '6':
        print("Netstat version: ",Netstat.netstat_version())
        snet.scan.scan(mac_addr, '-s')
        print(snet.scaninfo())
        print("Ip Status: ", Scanner[mac_addr].state())
        print(scanner [mac_addr].all_protocols())
        print("open ports: ", Scannner[mac_addr]['Ip'].keys())
elif resp>= '7':
        print("please enter a valid option")
# nmap                                          
ip_addr=input("Please Enter Target Ip Adress")
print("This ip you entered is: ",ip_addr)
type(ip_addr)

resp = input("""\n please enter the type of scan to run 
                                                1)SYN ACK scan
                                                2)UDP scansss
                                                3)Comprehens scan \n""")
print("You have selected option: ",resp)
if resp == '1':
    print("Nmap version: ",Scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024' '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", Scanner[ip_addr].state())
    print(scanner [ip_addr].all_protocols())
    print("open ports: ", Scannner[ip_addr]['tcp'].keys())
elif resp == '2':
        print("Nmap version: ",Scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024' '-v -sU')
        print(scanner.scaninfo())
        print("Ip Status: ", Scanner[ip_addr].state())
        print(scanner [ip_addr].all_protocols())
        print("open ports: ", Scannner[ip_addr]['Udp'].keys())
elif resp == '3':
        print("Nmap version: ",Scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024' '-v -sS -sV -sC -A -O')
        print(scanner.scaninfo())
        print("Ip Status: ", Scanner[ip_addr].state())
        print(scanner [ip_addr].all_protocols())
        print("open ports: ", Scannner[ip_addr]['tcp'].keys())
elif resp>= '4':
        print("please enter a valid option")