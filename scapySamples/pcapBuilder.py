from scapy.all import wrpcap, Ether, IP, UDP
packet = Ether() / IP(dst="1.2.3.4") / UDP(dport=123)
wrpcap('test_sample.pcap', [packet])