#include "../app/include/PacketProcessor.h"
#include "gtest/gtest.h"

// namespace
// {

// // Tests Factorial().

// // Tests factorial of 0.
// TEST(FactorialTest, Zero)
// {
//     EXPECT_EQ(1, Factorial(0));
// }

// }

namespace
{

class PacketProcessorTest : public ::testing::Test
{
  protected:
    PacketProcessor* packetProcessor;

    void SetUp() override
    {
        packetProcessor = new PacketProcessor();
    }

    void TearDown() override
    {
        // Code here will be called immediately after each test (right
        // before the destructor).
    }
};

TEST_F(PacketProcessorTest, InitializeReader)
{
    packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");
    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();
    // verify that a reader interface was indeed created
    ASSERT_NE(reader,         nullptr);
    // open the reader for reading
    ASSERT_EQ(reader->open(), true);
}

TEST_F(PacketProcessorTest, InitializeWriters) 
{
    packetProcessor->InitializeWriter("out_file.pcap");
    pcpp::PcapFileWriterDevice* writer = packetProcessor->getPacketWriter();

    ASSERT_TRUE(writer->open());
}

// TEST_F(PacketProcessorTest, FilterDataLinkLayerFromAllEthernetPcapFile) 
// {
//     pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

// 	pcpp::RawPacket rawPacket;

//     reader->getNextPacket(rawPacket);
// 	// while (reader->getNextPacket(rawPacket))
// 	// {
//     //     pcpp::Packet parsedPacket(&rawPacket);

//     //     // pcpp::Packet* outPacket = packetProcessor->FilterNonEthernet(&parsedPacket);
        
//     //     break;
//     //     // ASSERT_NE(outPacket, nullptr);
//     // }
// }

TEST(PacketFiltering, PcapFileWithOnlyEthernetPackets) 
{
    PacketProcessor* packetProcessor = new PacketProcessor();
    packetProcessor->InitializeReader("../scapySamples/test_sample.pcap");
    pcpp::IFileReaderDevice* reader = packetProcessor->getPacketReader();

    pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
        pcpp::Packet parsedPacket(&rawPacket);

        pcpp::Packet* outPacket = packetProcessor->FilterNonEthernet(&parsedPacket);
        
        // break;
        ASSERT_NE(outPacket, nullptr);
    }
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