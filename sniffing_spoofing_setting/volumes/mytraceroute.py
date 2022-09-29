#!/usr/bin/env python3

from scapy.all import *
from time import sleep

a = IP()
a.src = "10.178.0.2"
a.dst = "8.8.8.8"

for i in range(1, 6):
	a.ttl = i;
	b = ICMP()
	send(a/b)
	sleep(0.4)



