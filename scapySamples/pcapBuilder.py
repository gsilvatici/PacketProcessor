# from scapy.all import wrpcap, Ether, IP, UDP, PPP
from scapy.all import *

packet = Ether() / IP(dst="1.2.3.4") / UDP(dport=123)
wrpcap('1_eth_packet.pcap', [packet])

packet = PPP()
wrpcap('1_ppp_packet.pcap', [packet])

packet = Ether() / IP(dst="1.2.3.4")
wrpcap('1_ipv4_packet.pcap', [packet])

packet = Ether() / IPv6(dst="fe80::0123:4567")
wrpcap('1_ipv6_packet.pcap', [packet])
