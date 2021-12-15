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

    // open the reader for reading
    ASSERT_EQ(initStatus, true);

    delete packetProcessor;
}

// TEST(Initializer, InitializeWriter) 
// {
//     PacketProcessor* packetProcessor = new PacketProcessor();
//     packetProcessor->InitializeWriter("out_file.pcap");
//     pcpp::PcapFileWriterDevice* writer = packetProcessor->getPacketWriter();

//     ASSERT_TRUE(writer->open());

//     delete packetProcessor;
// }

TEST(PacketFiltering, PcapFileWithOnlyOneEthernetPacket) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");

    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	reader->getNextPacket(rawPacket);
    
    pcpp::Packet parsedPacket(&rawPacket);

    pcpp::Packet* outPacket = packetProcessor->FilterNonEthernet(&parsedPacket);
    
    ASSERT_NE(outPacket, nullptr);

    delete packetProcessor;
}

// TEST(PacketFiltering, PcapFileWithOnlyOneIPv4Packet) 
// {
//     PacketProcessor* packetProcessor = new PacketProcessor();
//     packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");

//     pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

//     pcpp::RawPacket rawPacket;
// 	reader->getNextPacket(rawPacket);
    
//     pcpp::Packet parsedPacket(&rawPacket);

//     pcpp::Packet* outPacket = nullptr;

//     if (packetProcessor->FiltersIpVersion()) 
//     {
//         outPacket = packetProcessor->FilterByIpVersion(&parsedPacket);    
//     }

//     ASSERT_NE(outPacket, nullptr);

//     delete packetProcessor;
// }

// TEST(PacketFiltering, PcapFileWithOnlyOneIPv6Packet) 
// {
//     PacketProcessor* packetProcessor = new PacketProcessor();
//     packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");

//     pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

//     pcpp::RawPacket rawPacket;
// 	reader->getNextPacket(rawPacket);
    
//     pcpp::Packet parsedPacket(&rawPacket);

//     pcpp::Packet* outPacket = nullptr;

//     if (packetProcessor->FiltersIpVersion()) 
//     {
//         outPacket = packetProcessor->FilterByIpVersion(&parsedPacket);    
//     }

//     ASSERT_NE(outPacket, nullptr);

//     delete packetProcessor;
// }

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