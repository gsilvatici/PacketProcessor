#ifndef PACKETPROCESSOR_H_
#define PACKETPROCESSOR_H_

#include <iostream>

#include "DnsLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "VlanLayer.h"

namespace pp
{
    class PacketProcessor
    {
      private:
        uint16_t vlanId;
        uint8_t ipVersion;
        uint8_t ttl;
        pcpp::IPAddress* dnsAddress;
        uint16_t dnsPort;
        std::shared_ptr<pcpp::IFileReaderDevice> reader;
        std::shared_ptr<pcpp::PcapFileWriterDevice> writer;
        bool filtersVLAN();
        bool filtersIpVersion();
        bool reducesTtl();
        bool replacesDnsAddress();
        bool replacesDnsPort();
        pcpp::Packet* processPacket(pcpp::Packet* parsedPacket);

      public:
        PacketProcessor();
        PacketProcessor(uint16_t vlanId, uint8_t ipVersion, uint8_t ttl, pcpp::IPAddress* dnsAddress, uint16_t dnsPort);
        ~PacketProcessor();
        void setVlanId(uint16_t vlanId);
        void setIpVersion(uint8_t ipVersion);
        void setTtl(uint8_t ttl);
        void setDnsAddress(pcpp::IPAddress* dnsAddress);
        void setDnsPort(uint16_t dnsPort);
        bool initializeReader(std::string inputFile);
        bool initializeWriter(std::string outputFile);
        pcpp::IFileReaderDevice* getPacketReader();
        pcpp::PcapFileWriterDevice* getPacketWriter();
        pcpp::Packet* filterVlanId(pcpp::Packet* parsedPacket);
        pcpp::Packet* filterNonEthernet(pcpp::Packet* parsedPacket);
        pcpp::Packet* filterIpVersion(pcpp::Packet* parsedPacket);
        pcpp::Packet* reduceTtl(pcpp::Packet* parsedPacket);
        pcpp::Packet* filterIcmp(pcpp::Packet* parsedPacket);
        pcpp::Packet* replaceDnsAddress(pcpp::Packet* parsedPacket);
        pcpp::Packet* replaceDnsPort(pcpp::Packet* parsedPacket);
        int processFile(std::string inputFile, std::string outputFile);
    };
}

#endif // PACKETROCESSOR_H
