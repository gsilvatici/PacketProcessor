#ifndef GTEST_PACKETPROCESSOR_H_
#define GTEST_PACKETPROCESSOR_H_

#include "PcapFileDevice.h"
#include "Packet.h"

// #include <PcapPlusPlusVersion.h>
// #include <SystemUtils.h>
// #include "stdlib.h"

class PacketProcessor
{
  private:
    //uint16_t
    int vlanId;
    int ipVersion;
    int ttl;
    int dnsAddress;
    int dnsPort;
    pcpp::IFileReaderDevice* reader;
    pcpp::PcapFileWriterDevice* writer;

  public:
    PacketProcessor();
    PacketProcessor(int vlanId, int ipVersion, int ttl, int dnsAddress, int dnsPort);
    bool FiltersByVLAN();
    bool FiltersIpVersion();
    bool ReducesTTL();
    bool ReplacesDnsAddress();
    bool ReplacesDnsPort();
    void InitializeReader(std::string inputFile);
    void InitializeWriter(std::string outputFile);
    pcpp::IFileReaderDevice*    getPacketReader();
    pcpp::PcapFileWriterDevice* getPacketWriter();
    pcpp::Packet* FilterNonEthernet(pcpp::Packet* parsedPacket);
    // public ProcessPacket(pcpp::RawPacket rawPacket);
};

#endif // GTEST_PACKETROCESSOR_H
