#ifndef GTEST_PACKETPROCESSOR_H_
#define GTEST_PACKETPROCESSOR_H_

#include <iostream>

#include "PcapFileDevice.h"
#include "Packet.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
// #include "ICMP.h"
// #include <PcapPlusPlusVersion.h>
// #include <SystemUtils.h>
// #include "stdlib.h"

class PacketProcessor
{
  private:
    uint16_t vlanId;
    int ipVersion;
    int ttl;
    int dnsAddress;
    int dnsPort;
    pcpp::IFileReaderDevice* reader;
    pcpp::PcapFileWriterDevice* writer;

  public:
    PacketProcessor();
    PacketProcessor(int vlanId, int ipVersion, int ttl, int dnsAddress, int dnsPort);
    ~PacketProcessor();
    void setVlanId(int vlanId);
    void setIpVersion(int ipVersion);
    void setTTL(int ttl);
    void setDnsAddress(int dnsAddress);
    void setDnsPort(int dnsPort);
    bool FiltersVLAN();
    bool FiltersIpVersion();
    bool ReducesTTL();
    bool ReplacesDnsAddress();
    bool ReplacesDnsPort();
    bool InitializeReader(std::string inputFile);
    bool InitializeWriter(std::string outputFile);
    pcpp::IFileReaderDevice*    getPacketReader();
    pcpp::PcapFileWriterDevice* getPacketWriter();
    pcpp::Packet* FilterVlanId(pcpp::Packet* parsedPacket);
    pcpp::Packet* FilterNonEthernet(pcpp::Packet* parsedPacket);
    pcpp::Packet* FilterIpVersion(pcpp::Packet* parsedPacket);
    pcpp::Packet* ReduceTTL(pcpp::Packet* parsedPacket);
    pcpp::Packet* FilterICMP(pcpp::Packet* parsedPacket);
    pcpp::Packet* ReplaceDnsAddress(pcpp::Packet* parsedPacket);
    pcpp::Packet* ReplaceDnsPort(pcpp::Packet* parsedPacket);
    // public ProcessPacket(pcpp::RawPacket rawPacket);
};

#endif // GTEST_PACKETROCESSOR_H
