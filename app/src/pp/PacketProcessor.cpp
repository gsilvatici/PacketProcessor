#include "pp/PacketProcessor.h"

using namespace pp;
using namespace pcpp;

PacketProcessor::PacketProcessor()
{
    this->vlanId = -1;
    this->ipVersion = -1;
    this->ttl = -1;
    this->dnsAddress = nullptr;
    this->dnsPort = -1;
    this->reader = nullptr;
    this->writer = nullptr;
}

PacketProcessor::PacketProcessor(uint16_t vlanId, uint8_t ipVersion, uint8_t ttl, IPAddress* dnsAddress, uint16_t dnsPort)
    : vlanId(vlanId), ipVersion(ipVersion), ttl(ttl), dnsAddress(dnsAddress), dnsPort(dnsPort), reader(nullptr), writer(nullptr)
{
}

PacketProcessor::~PacketProcessor()
{
    if(reader) {
        reader->close();
    }   
    if(writer) {
        writer->close();
    }
}

void PacketProcessor::setVlanId(uint16_t vlanId)
{
    this->vlanId = vlanId;
}

void PacketProcessor::setIpVersion(uint8_t ipVersion)
{
    this->ipVersion = ipVersion;
}

void PacketProcessor::setTtl(uint8_t ttl)
{
    this->ttl = ttl;
}

void PacketProcessor::setDnsAddress(IPAddress* dnsAddress)
{
    this->dnsAddress = dnsAddress;
}

void PacketProcessor::setDnsPort(uint16_t dnsPort)
{
    this->dnsPort = dnsPort;
}

bool PacketProcessor::filtersVLAN()
{
    return this->vlanId == -1 ? false : true;
}

bool PacketProcessor::filtersIpVersion()
{
    return this->ipVersion == -1 ? false : true;
}

bool PacketProcessor::reducesTtl()
{
    return this->ttl == -1 ? false : true;
}

bool PacketProcessor::replacesDnsAddress()
{
    return this->dnsAddress == nullptr ? false : true;
}

bool PacketProcessor::replacesDnsPort()
{
    return this->dnsPort == -1 ? false : true;
}

bool PacketProcessor::initializeReader(std::string inputFile)
{
    reader.reset(IFileReaderDevice::getReader(inputFile));
    if (reader) {
        return reader->open();
    }
    return false; 
}

bool PacketProcessor::initializeWriter(std::string outputFile)
{
    writer.reset(new PcapFileWriterDevice(outputFile, LINKTYPE_ETHERNET));
    if (writer) {
        return writer->open();
    } 
    return false;  
}

IFileReaderDevice* PacketProcessor::getPacketReader()
{
    return reader.get();
}

PcapFileWriterDevice* PacketProcessor::getPacketWriter()
{
    return writer.get();
}

Packet* PacketProcessor::filterVlanId(Packet* parsedPacket)
{
    if (this->filtersVLAN()) {
        auto vlanLayer = parsedPacket->getLayerOfType<VlanLayer>();
        // if (vlanLayer == NULL)
        // {
        //     std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
        // }
        if (this->vlanId == vlanLayer->getVlanID()) {
              return parsedPacket;
        }
    }
    return nullptr;
}

Packet* PacketProcessor::filterNonEthernet(Packet* parsedPacket)
{
    if(parsedPacket->isPacketOfType(Ethernet)) {
        return parsedPacket;
    }
    return nullptr;
}

Packet* PacketProcessor::filterIpVersion(Packet* parsedPacket)
{
    if (this->filtersIpVersion()) {
        switch(this->ipVersion)
            {
            case 4:
                if(parsedPacket->isPacketOfType(IPv4))
                    return parsedPacket;
            break;

            case 6:
                if(parsedPacket->isPacketOfType(IPv6))
                    return parsedPacket;
            break;
        // if ((this->ipVersion == 4 && parsedPacket->isPacketOfType(IPv4)) ||
        //     (this->ipVersion == 6 && parsedPacket->isPacketOfType(IPv6))) {
        //       return parsedPacket;
        }
    }
    return nullptr;
}

Packet* PacketProcessor::reduceTtl(Packet* parsedPacket)
{
    if (this->reducesTtl()) {
        if(parsedPacket->isPacketOfType(IPv4)) {
            auto ipLayer = parsedPacket->getLayerOfType<IPv4Layer>();
            if (this->ttl < ipLayer->getIPv4Header()->timeToLive) {
                ipLayer->getIPv4Header()->timeToLive -= this->ttl;
                return parsedPacket;
            }
        }
        if(parsedPacket->isPacketOfType(IPv6)) {
            auto ipLayer = parsedPacket->getLayerOfType<IPv6Layer>();
            if (this->ttl < ipLayer->getIPv6Header()->hopLimit) {
                ipLayer->getIPv6Header()->hopLimit -= this->ttl;
                return parsedPacket;
            } 
        }
    }
    return nullptr;
}

Packet* PacketProcessor::filterIcmp(Packet* parsedPacket)
{
    if(!parsedPacket->isPacketOfType(ICMP)) {
        return parsedPacket;
    }
    return nullptr;
}

Packet* PacketProcessor::replaceDnsAddress(Packet* parsedPacket)
{
    if (this->replacesDnsAddress()) {
        return parsedPacket;
    }
    return nullptr;
}

Packet* PacketProcessor::replaceDnsPort(Packet* parsedPacket)
{    
    if (this->replacesDnsPort()) {
        if(parsedPacket->isPacketOfType(UDP) && parsedPacket->isPacketOfType(DNS)) {
            // DnsLayer* dnsLayer = parsedPacket->getLayerOfType<DnsLayer>();
            return parsedPacket;
        }
    }
    return nullptr;
}
