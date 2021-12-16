#include "../app/include/PacketProcessor.h"
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
    bool initStatus = packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");

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

TEST(PacketFiltering, FileWithOnlyOneEthernetPacket) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../scapySamples/1_eth_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->FilterNonEthernet(&parsedPacket);
    
    //Since it is a ethernet packet it should not filter it and return it back
    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(PacketFiltering, FileWithOnlyOneNonEthernetPacket) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../scapySamples/1_ppp_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();
    pcpp::RawPacket rawPacket;
    reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);

    //Since it is not an ethernet packet (is a PPP) it should filter it and return null
    pcpp::Packet* outPacket = packetProcessor->FilterNonEthernet(&parsedPacket);
    
    ASSERT_EQ(outPacket, nullptr);

    delete packetProcessor;
}

TEST(PacketFiltering, FileWithOnlyOneIPv4PacketToFilterIPv6) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(4);
    packetProcessor->InitializeReader("../scapySamples/1_ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterByIpVersion(&parsedPacket);    
    }

    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

TEST(PacketFiltering, FileWithOnlyOneIPv4PacketToFilterIPv4) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(6);
    packetProcessor->InitializeReader("../scapySamples/1_ipv4_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterByIpVersion(&parsedPacket);    
    }

    ASSERT_EQ(outPacket, nullptr);

    delete packetProcessor;
}

TEST(PacketFiltering, FileWithOnlyOneIPv6PacketToFilterIPv6) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(4);
    packetProcessor->InitializeReader("../scapySamples/1_ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    pcpp::Packet parsedPacket(&rawPacket);
    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterByIpVersion(&parsedPacket);    
    }

    ASSERT_EQ(outPacket, nullptr);

    delete packetProcessor;
}

TEST(PacketFiltering, FileWithOnlyOneIPv6PacketToFilterIPv4) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->setIpVersion(6);
    packetProcessor->InitializeReader("../scapySamples/1_ipv6_packet.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	  reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = nullptr;

    if (packetProcessor->FiltersIpVersion()) {
        outPacket = packetProcessor->FilterByIpVersion(&parsedPacket);    
    }

    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

// TEST(PacketFiltering, PcapFileWithOnlyOneVlanIdOfCeroPacket) 
// {
//     PacketProcessor* packetProcessor = new PacketProcessor();
//     packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");

//     pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

//     pcpp::RawPacket rawPacket;
// 	reader->getNextPacket(rawPacket);
    
//     pcpp::Packet parsedPacket(&rawPacket);

//     pcpp::Packet* outPacket = nullptr;

//     if (packetProcessor->FiltersByVLAN()) 
//     {
//         // outPacket = packetProcessor->FilterByVLAN(&parsedPacket);    
//     }

//     ASSERT_NE(outPacket, nullptr);

//     delete packetProcessor;
// }

// TEST(PacketFiltering, PcapFileWithOnlyOneICMPPacket) 
// {
//     PacketProcessor* packetProcessor = new PacketProcessor();
//     packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");

//     pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

//     pcpp::RawPacket rawPacket;
// 	reader->getNextPacket(rawPacket);
    
//     pcpp::Packet parsedPacket(&rawPacket);

//     // pcpp::Packet* outPacket = outPacket = packetProcessor->FilterICMP(&parsedPacket);    
   
//     // ASSERT_NE(outPacket, nullptr);

//     delete packetProcessor;
// }

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