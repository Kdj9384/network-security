#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

#pkt = sniff(iface=['br-1bfc3864daa5', 'ens4'], filter='icmp', prn=print_pkt)

pkt = sniff(iface=['ens4'], filter='icmp', prn=print_pkt)
#pkt = sniff(iface='ens4', filter='icmp', prn=print_pkt)
#pkt = sniff(iface='br-1bfc3864daa5', filter='ip proto tcp dst port 23', prn=print_pkt)





