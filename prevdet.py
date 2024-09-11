from scapy.all import sniff
from collections import defaultdict
import time
import os

# Configuration
IP_THRESHOLD = 100  
BLOCK_TIME = 10     
TIME_WINDOW = 60    

packet_counts = defaultdict(int)
start_time = time.time()
blocked_ips = defaultdict(float) 

def block_ip(ip_src):
    """Block IP using iptables (Linux specific)"""
    print(f"Blocking IP: {ip_src}")
    os.system(f"sudo iptables -A INPUT -s {ip_src} -j DROP") 
def unblock_ip(ip_src):
    """Unblock IP using iptables"""
    print(f"Unblocking IP: {ip_src}")
    os.system(f"sudo iptables -D INPUT -s {ip_src} -j DROP")  
def detect_ddos_attack(pkt):
    global start_time


    current_time = time.time()

    if pkt.haslayer('IP'):
        ip_src = pkt['IP'].src
        
        
        if ip_src in blocked_ips and current_time < blocked_ips[ip_src]:
            return 
        if ip_src in blocked_ips and current_time >= blocked_ips[ip_src]:
    
            unblock_ip(ip_src)
            del blocked_ips[ip_src]

        
        packet_counts[ip_src] += 1

       
        if packet_counts[ip_src] > IP_THRESHOLD:
            print(f"[WARNING] Potential DDoS attack detected from IP: {ip_src}. Blocking IP for {BLOCK_TIME} seconds.")
            block_ip(ip_src)
            blocked_ips[ip_src] = current_time + BLOCK_TIME
            packet_counts[ip_src] = 0 
    
        if current_time - start_time > TIME_WINDOW:
            packet_counts.clear()
            start_time = current_time

print("Starting packet sniffing. Press Ctrl+C to stop.")
try:
    sniff(prn=detect_ddos_attack, store=0)
except KeyboardInterrupt:
    print("Packet sniffing stopped.")
    if not packet_counts:
        print("Network traffic is normal. All IPs are safe.")