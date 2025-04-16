import socket
import os
from scapy.all import *

# 1. Scan open ports
def port_scanner(ip, ports):
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET.socket.SOCK_STREAM)
            if sock.connect_ex((ip, port)) == 0:
                print(f"Port {port} open")
        except: pass

# 2. Ping a device
def ping_device(ip): os.system(f"ping -c 4 {ip}")

# 3. Discover devices
def arp_scan(): print([p[ARP].psrc for p in 
                       srp(Ether(dst="ff:ff:ff:ff:ff:ff")/
                            ARP(pdst="192.168.1.0/24"), timeout=2)[0]])

# 4. Trace route
def trace_route(ip): os.system(f"traceroute{ip}")

# 5. Host information
def host_info(domain):
    print(socket.gethostbyname(domain))