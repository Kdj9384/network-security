#!/usr/bin/env python3
from scapy.all import *

counter = 0;

def print_pkt(pkt):
	global counter 
	print(counter)
	counter += 1
	pkt.show()

pkt = sniff(iface='br-1bfc3864daa5',  prn=print_pkt)
#pkt = sniff(iface=['br-1bfc3864daa5','ens4', 'docker0' ], prn=print_pkt)
#pkt = sniff(iface='br-1bfc3864daa5', filter='arp', prn=print_pkt)
