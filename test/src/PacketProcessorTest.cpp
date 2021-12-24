#include "pp/PacketProcessor.h"
#include "gtest/gtest.h"

using namespace pp;
using namespace std;

namespace
{
class PacketProcessorTest : public ::testing::Test
{
  protected:

    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

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

TEST(FilterPacketWithVlanIdNotEqual23, DISABLED_FromFileWithOnlyOnePacketAndDistinctId) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    uint16_t vlanId = 23;
    packetProcessor->setVlanId(vlanId);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet_bis.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    
    pcpp::Packet* outPacket = packetProcessor->filterVlanId(&parsedPacket);

    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterPacketWithVlanIdNotEqual23, DISABLED_FromFileWithOnlyOnePacketAndSameId) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setVlanId(23);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = packetProcessor->filterVlanId(&parsedPacket);
  
    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterEthernetPacket, FromFileWithOnlyOneEthernetPacket) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/eth_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->filterNonEthernet(&parsedPacket);
    
    //Since it is a ethernet packet it should not filter it and return it back
    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterEthernetPacket, FromFileWithOnlyOneNonEthernetPacket) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ppp_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();
    pcpp::RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);

    //Since it is not an ethernet packet (is a PPP) it should filter it and return null
    pcpp::Packet* outPacket = packetProcessor->filterNonEthernet(&parsedPacket);
    
    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterIPv6Packet, FromFileWithOnlyOneIPv4Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)4);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterIPv6Packet, FromFileWithOnlyOneIPv6Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)4);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterIPv4Packet, FromFileWithOnlyOneIPv4Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)6);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_EQ(outPacket, nullptr);
}

TEST(FilterIPv4Packet, FromFileWithOnlyOneIPv6Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setIpVersion((uint8_t)6);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->filterIpVersion(&parsedPacket);    

    ASSERT_NE(outPacket, nullptr);
}

TEST(ReduceTTL, FromFileWithOnlyOneIPv4Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setTtl(5);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->reduceTtl(&parsedPacket);    

    pcpp::IPv4Layer* ipLayer = outPacket->getLayerOfType<pcpp::IPv4Layer>();
    int packetTTL = ipLayer->getIPv4Header()->timeToLive;

    ASSERT_EQ(packetTTL, 15);
}

TEST(ReduceTTL, FromFileWithOnlyOneIPv6Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->setTtl(19);
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->reduceTtl(&parsedPacket);    

    pcpp::IPv6Layer* ipLayer = outPacket->getLayerOfType<pcpp::IPv6Layer>();
    int packetTTL = ipLayer->getIPv6Header()->hopLimit;

    ASSERT_EQ(packetTTL, 1);
}

TEST(FilterICMPPacket, FromFileWithOnlyOneIPv4Packet) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->filterIcmp(&parsedPacket);

    ASSERT_NE(outPacket, nullptr);
}

TEST(FilterICMPPacket, FromFileWithOnlyOneICMPPacket) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/icmp_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->filterIcmp(&parsedPacket);

    ASSERT_NE(outPacket, nullptr);
}

TEST(ReplaceDnsAddressAndPort, DISABLED_FromFileWithOnlyOneTCPPacketWithDNSLayer) 
{
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    // packetProcessor->setDnsAddress();
    packetProcessor->initializeReader("../test/data/capture/single_packet_pcaps/ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    outPacket = packetProcessor->replaceDnsAddress(&parsedPacket);    

    outPacket = packetProcessor->replaceDnsPort(&parsedPacket);    

    ASSERT_NE(outPacket, nullptr);
}

}

#ifdef TESTING
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
#endif