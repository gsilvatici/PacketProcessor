# from scapy.all import wrpcap, Ether, IP, UDP, PPP
from scapy.all import *

packet = Ether() / IP(dst="1.2.3.4") / UDP(dport=123)
wrpcap('../test/data/capture/single_packet_pcaps/eth_packet.pcap', [packet])

packet = PPP()
wrpcap('../test/data/capture/single_packet_pcaps/ppp_packet.pcap', [packet])

packet = Ether() / IP(dst="1.2.3.4", src="1.2.3.4", ttl=20) / Dot1Q(vlan=23)
wrpcap('../test/data/capture/single_packet_pcaps/ipv4_packet.pcap', [packet])

packet = Ether() / IP(dst="1.2.3.4", src="1.2.3.4") / Dot1Q(vlan=4094)
wrpcap('../test/data/capture/single_packet_pcaps/ipv4_packet_bis.pcap', [packet])

packet = Ether() / IPv6(dst="fe80::0123:4567", hlim=20)
wrpcap('../test/data/capture/single_packet_pcaps/ipv6_packet.pcap', [packet])

packet = ICMP()
wrpcap('../test/data/capture/single_packet_pcaps/icmp_packet.pcap', [packet])

packet = Ether() / IP(dst="1.2.3.4", src="4.3.2.1") / UDP(dport=123)  
wrpcap('../test/data/capture/single_packet_pcaps/udp_dns_packet.pcap', [packet])