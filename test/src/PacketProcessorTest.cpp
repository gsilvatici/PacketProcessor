#include "gtest/gtest.h"

#include "pp/PacketProcessor.h"

using namespace std;
using namespace pcpp;
using namespace pp;

TEST(Initializer, InitializeReader)
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    bool initStatus = packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/eth_packet.pcap");

    ASSERT_EQ(initStatus, true);    
}

TEST(Initializer, InitializeWriter) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    bool initStatus = packetProcessor->initializeWriter("out_file.pcap");

    ASSERT_EQ(initStatus, true);
}

TEST(FilterPacketWithVlanIdNotEqual30, DISABLED_FromFileWithOnlyOneVlanPacketAndDistinctId) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    uint16_t vlanId = 28;
    packetProcessor->setVlanId(vlanId);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/vlan_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    Packet parsedPacket(&rawPacket);
    Packet* outPacket = nullptr;
    
    outPacket = packetProcessor->filterVlanId(&parsedPacket);

    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterPacketWithVlanIdNotEqual30, FromFileWithOnlyOneVlanPacketAndSameId) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setVlanId(30);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/vlan_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    Packet parsedPacket(&rawPacket);
    Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterVlanId(&parsedPacket);
  
    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterEthernetPacket, FromFileWithOnlyOneEthernetPacket) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/eth_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    Packet parsedPacket(&rawPacket);
    Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterNonEthernet(&parsedPacket);
    
    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterEthernetPacket, FromFileWithOnlyOneNonEthernetPacket) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ppp_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();
    RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    Packet parsedPacket(&rawPacket);
    Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterNonEthernet(&parsedPacket);
    
    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterIPv6Packet, FromFileWithOnlyOneIPv4Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)4);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    Packet parsedPacket(&rawPacket);
    Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterIPv6Packet, FromFileWithOnlyOneIPv6Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)4);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    Packet parsedPacket(&rawPacket);
    Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterIPv4Packet, FromFileWithOnlyOneIPv4Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)6);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    Packet parsedPacket(&rawPacket);
    Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterIPv4Packet, FromFileWithOnlyOneIPv6Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)6);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    Packet parsedPacket(&rawPacket);

    Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_NE(outPacket, nullptr);
}

TEST(ReduceTTL, FromFileWithOnlyOneIPv4Packet) 
{
    // unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    // packetProcessor->setTtl(5);
    // packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    // IFileReaderDevice* reader = packetProcessor->getPacketReader();

    // RawPacket rawPacket;
	  // reader->getNextPacket(rawPacket);
    
    // Packet parsedPacket(&rawPacket);

    // Packet* outPacket = nullptr;

    // outPacket = packetProcessor->reduceTtl(&parsedPacket);    

    // IPv4Layer* ipLayer = outPacket->getLayerOfType<pcpp::IPv4Layer>();
    // int packetTTL = ipLayer->getIPv4Header()->timeToLive;

    // ASSERT_EQ(packetTTL, 15);
}

TEST(ReduceTTL, FromFileWithOnlyOneIPv6Packet) 
{
    // unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    // packetProcessor->setTtl(19);
    // packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    // IFileReaderDevice* reader = packetProcessor->getPacketReader();

    // RawPacket rawPacket;
	  // reader->getNextPacket(rawPacket);
    
    // Packet parsedPacket(&rawPacket);

    // Packet* outPacket = nullptr;

    // outPacket = packetProcessor->reduceTtl(&parsedPacket);    

    // IPv6Layer* ipLayer = outPacket->getLayerOfType<pcpp::IPv6Layer>();
    // int packetTTL = ipLayer->getIPv6Header()->hopLimit;

    // ASSERT_EQ(packetTTL, 1);
}

TEST(FilterICMPPacket, FromFileWithOnlyOneIPv4Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    Packet parsedPacket(&rawPacket);

    Packet* outPacket = packetProcessor->filterIcmp(&parsedPacket);

    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterICMPPacket, FromFileWithOnlyOneICMPPacket) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/icmp_packet.pcap");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    Packet parsedPacket(&rawPacket);

    Packet* outPacket = packetProcessor->filterIcmp(&parsedPacket);

    ASSERT_NE(outPacket, nullptr);
}

TEST(ReplaceDnsServerAddress, FromFileWithOnlyOneUDPIpV4PacketWithDNSRequest) 
{
    // unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    // packetProcessor->setDnsAddress(IPAddress("192.168.5.5"));
    // packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/dns_request_packet.pcapng");

    // IFileReaderDevice* reader = packetProcessor->getPacketReader();

    // RawPacket rawPacket;
	  // reader->getNextPacket(rawPacket);
    
    // Packet parsedPacket(&rawPacket);

    // packetProcessor->replaceDnsAddress(&parsedPacket);    

    // IPAddress serverAddress = parsedPacket.getLayerOfType<IPv4Layer>()->getDstIPv4Address();

    // ASSERT_EQ(serverAddress.getIPv4().toString(), "192.168.5.5");
}

TEST(ReplaceDnsServerAddress, FromFileWithOnlyOneUDPIpV4PacketWithDNSResponse) 
{
    // unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    // packetProcessor->setDnsAddress(IPAddress("192.168.5.5"));
    // packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/dns_response_packet.pcapng");

    // IFileReaderDevice* reader = packetProcessor->getPacketReader();

    // RawPacket rawPacket;
	  // reader->getNextPacket(rawPacket);
    
    // Packet parsedPacket(&rawPacket);

    // packetProcessor->replaceDnsAddress(&parsedPacket);    

    // IPAddress serverAddress = parsedPacket.getLayerOfType<IPv4Layer>()->getSrcIPv4Address();

    // ASSERT_EQ(serverAddress.getIPv4().toString(), "192.168.5.5");
}

TEST(ReplaceDnsServerAddress, DISABLED_FromFileWithOnlyOneUDPIpV6PacketWithDNSRequest) 
{
//     unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
//     packetProcessor->setDnsAddress(IPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
//     packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/dns_request_packet.pcapng");

//     IFileReaderDevice* reader = packetProcessor->getPacketReader();

//     RawPacket rawPacket;
// 	  reader->getNextPacket(rawPacket);
    
//     Packet parsedPacket(&rawPacket);

//     packetProcessor->replaceDnsAddress(&parsedPacket);    

//     IPAddress serverAddress = parsedPacket.getLayerOfType<IPv6Layer>()->getDstIPv6Address();

//     ASSERT_EQ(serverAddress.getIPv6().toString(), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
}

TEST(ReplaceDnsServerAddress, DISABLED_FromFileWithOnlyOneUDPIpV6PacketWithDNSResponse) 
{
    // unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    // packetProcessor->setDnsAddress(IPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    // packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/dns_response_packet.pcapng");

    // IFileReaderDevice* reader = packetProcessor->getPacketReader();

    // RawPacket rawPacket;
	  // reader->getNextPacket(rawPacket);
    
    // Packet parsedPacket(&rawPacket);

    // packetProcessor->replaceDnsAddress(&parsedPacket);    

    // IPAddress serverAddress = parsedPacket.getLayerOfType<IPv6Layer>()->getSrcIPv6Address();

    // ASSERT_EQ(serverAddress.getIPv6().toString(), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
}

TEST(ReplaceDnsServerPort, FromFileWithOnlyOneUDPIpV4PacketWithDNSRequest) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setDnsPort(658);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/dns_request_packet.pcapng");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    Packet parsedPacket(&rawPacket);

    packetProcessor->replaceDnsPort(&parsedPacket);

    uint16_t serverPort = htons(parsedPacket.getLayerOfType<UdpLayer>()->getUdpHeader()->portDst);

    ASSERT_EQ(serverPort, 658);
}

TEST(ReplaceDnsServerPort, FromFileWithOnlyOneUDPIpV4PacketWithDNSResponse) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setDnsPort(658);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/dns_response_packet.pcapng");

    IFileReaderDevice* reader = packetProcessor->getPacketReader();

    RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    Packet parsedPacket(&rawPacket);

    packetProcessor->replaceDnsPort(&parsedPacket);    

    uint16_t serverPort = htons(parsedPacket.getLayerOfType<UdpLayer>()->getUdpHeader()->portSrc);

    ASSERT_EQ(serverPort, 658);
}

TEST(FilterTcpPackets, FromFileWithMultipleTcpPackets) 
{
	  // create the TCP reassembly instance
  	// pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);

}

int main(int argc, char **argv)
{
        ::testing::InitGoogleTest(&argc, argv);
        std::cout << "RUNNING TESTS ..." << std::endl;
        int ret{RUN_ALL_TESTS()};
        if (!ret)
            std::cout << "<<<SUCCESS>>>" << std::endl;
        else
            std::cout << "FAILED" << std::endl;
        return 0;
}