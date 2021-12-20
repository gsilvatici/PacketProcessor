#include "../../app/include/PacketProcessor.h"
#include "gtest/gtest.h"

namespace
{
class PacketProcessorTest : public ::testing::Test
{
  protected:
    // PacketProcessor* packetProcessor;

    void SetUp() override
    {
        // packetProcessor = new PacketProcessor();
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).
    }
};

TEST(Initializer, InitializeReader)
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    bool initStatus = packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/eth_packet.pcap");

    ASSERT_EQ(initStatus, true);

    delete packetProcessor;
}

TEST(Initializer, InitializeWriter) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    bool initStatus = packetProcessor->InitializeWriter("out_file.pcap");

    ASSERT_EQ(initStatus, true);

    delete packetProcessor;
}

TEST(FilterPacketWithVlanIdNotEqual23, DISABLED_FromFileWithOnlyOnePacketAndDistinctId) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setVlanId(23);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet_bis.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    
    pcpp::Packet* outPacket = packetProcessor->FilterVlanId(&parsedPacket);

    ASSERT_EQ(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterPacketWithVlanIdNotEqual23, DISABLED_FromFileWithOnlyOnePacketAndSameId) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setVlanId(23);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = packetProcessor->FilterVlanId(&parsedPacket);
  
    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterEthernetPacket, FromFileWithOnlyOneEthernetPacket) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/eth_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->FilterNonEthernet(&parsedPacket);
    
    //Since it is a ethernet packet it should not filter it and return it back
    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterEthernetPacket, FromFileWithOnlyOneNonEthernetPacket) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ppp_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();
    pcpp::RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);

    //Since it is not an ethernet packet (is a PPP) it should filter it and return null
    pcpp::Packet* outPacket = packetProcessor->FilterNonEthernet(&parsedPacket);
    
    ASSERT_EQ(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterIPv6Packet, FromFileWithOnlyOneIPv4Packet) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(4);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterIpVersion(&parsedPacket);    
    }

    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterIPv6Packet, FromFileWithOnlyOneIPv6Packet) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(4);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterIpVersion(&parsedPacket);    
    }

    ASSERT_EQ(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterIPv4Packet, FromFileWithOnlyOneIPv4Packet) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(6);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterIpVersion(&parsedPacket);    
    }

    ASSERT_EQ(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterIPv4Packet, FromFileWithOnlyOneIPv6Packet) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(6);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterIpVersion(&parsedPacket);    
    }

    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(ReduceTTL, FromFileWithOnlyOneIPv4Packet) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setTTL(5);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->ReducesTTL()) {
        outPacket = packetProcessor->ReduceTTL(&parsedPacket);    
    }

    pcpp::IPv4Layer* ipLayer = outPacket->getLayerOfType<pcpp::IPv4Layer>();
    int packetTTL = ipLayer->getIPv4Header()->timeToLive;

    ASSERT_EQ(packetTTL, 15);

    delete packetProcessor;
}

TEST(ReduceTTL, FromFileWithOnlyOneIPv6Packet) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setTTL(19);
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->ReducesTTL()) {
        outPacket = packetProcessor->ReduceTTL(&parsedPacket);    
    }

    pcpp::IPv6Layer* ipLayer = outPacket->getLayerOfType<pcpp::IPv6Layer>();
    int packetTTL = ipLayer->getIPv6Header()->hopLimit;

    ASSERT_EQ(packetTTL, 1);

    delete packetProcessor;
}

TEST(FilterICMPPacket, FromFileWithOnlyOneIPv4Packet) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->FilterICMP(&parsedPacket);

    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(FilterICMPPacket, FromFileWithOnlyOneICMPPacket) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/icmp_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->FilterICMP(&parsedPacket);

    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(ReplaceDnsAddressAndPort, DISABLED_FromFileWithOnlyOneTCPPacketWithDNSLayer) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    // packetProcessor->setDnsAddress();
    packetProcessor->InitializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->ReplaceDnsAddress(&parsedPacket);    

    outPacket = packetProcessor->ReplaceDnsPort(&parsedPacket);    

    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}




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