# from scapy.all import wrpcap, Ether, IP, UDP, PPP
from scapy.all import *

packet = Ether() / IP(dst="1.2.3.4") / UDP(dport=123)
wrpcap('1_eth_packet.pcap', [packet])

packet = PPP()
wrpcap('1_ppp_packet.pcap', [packet])

packet = Ether() / IP(dst="1.2.3.4", src="1.2.3.4", ttl=20) / Dot1Q(vlan=23)
wrpcap('1_ipv4_packet.pcap', [packet])

packet = Ether() / IP(dst="1.2.3.4", src="1.2.3.4") / Dot1Q(vlan=4094)
wrpcap('1_ipv4_packet_bis.pcap', [packet])

packet = Ether() / IPv6(dst="fe80::0123:4567", hlim=20)
wrpcap('1_ipv6_packet.pcap', [packet])

packet = ICMP()
wrpcap('1_icmp_packet.pcap', [packet])

packet = Ether() / IP(dst="1.2.3.4") / TCP(dport=123) / 
wrpcap('1_tcp_dns_packet.pcap', [packet])