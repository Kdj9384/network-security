#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.src="8.8.8.8"
a.dst = "10.9.0.6"
b = ICMP()
p = a/b
send(p)
