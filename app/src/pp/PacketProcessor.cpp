// #include "../../include/pp/PacketProcessor.h"
#include "pp/PacketProcessor.h"

using namespace pp;

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

PacketProcessor::PacketProcessor(uint16_t vlanId, uint8_t ipVersion, uint8_t ttl, pcpp::IPAddress* dnsAddress, uint16_t dnsPort)
    : vlanId(vlanId), ipVersion(ipVersion), ttl(ttl), dnsAddress(dnsAddress), dnsPort(dnsPort), reader(nullptr), writer(nullptr)
{
}

PacketProcessor::~PacketProcessor()
{
    if(reader) {
        reader->close();
        delete reader;
    }   
    if(writer) {
        writer->close();
        delete writer;
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

void PacketProcessor::setDnsAddress(pcpp::IPAddress* dnsAddress)
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
    reader = pcpp::IFileReaderDevice::getReader(inputFile);
    if (reader != nullptr) {
        // bool ret = reader->open();
        // if (this->FiltersVLAN()) {
        //     pcpp::VlanFilter vlanFilter(this->vlanId);
        //     reader->setFilter(vlanFilter);
        // }
        return reader->open();
    } else {
        return false;        
    }   
}

bool PacketProcessor::initializeWriter(std::string outputFile)
{
    writer = new pcpp::PcapFileWriterDevice(outputFile, pcpp::LINKTYPE_ETHERNET);
    return writer->open();
}

pcpp::IFileReaderDevice* PacketProcessor::getPacketReader()
{
    return this->reader;
}

pcpp::PcapFileWriterDevice* PacketProcessor::getPacketWriter()
{
    return this->writer;
}

pcpp::Packet* PacketProcessor::filterVlanId(pcpp::Packet* parsedPacket)
{
    if (this->filtersVLAN()) {
        auto vlanLayer = parsedPacket->getLayerOfType<pcpp::VlanLayer>();
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

pcpp::Packet* PacketProcessor::filterNonEthernet(pcpp::Packet* parsedPacket)
{
    if(parsedPacket->isPacketOfType(pcpp::Ethernet)) {
        return parsedPacket;
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::filterIpVersion(pcpp::Packet* parsedPacket)
{
    if (this->filtersIpVersion()) {
        switch(this->ipVersion)
            {
            case 4:
                if(parsedPacket->isPacketOfType(pcpp::IPv4))
                    return parsedPacket;
            break;

            case 6:
                if(parsedPacket->isPacketOfType(pcpp::IPv6))
                    return parsedPacket;
            break;
        // if ((this->ipVersion == 4 && parsedPacket->isPacketOfType(pcpp::IPv4)) ||
        //     (this->ipVersion == 6 && parsedPacket->isPacketOfType(pcpp::IPv6))) {
        //       return parsedPacket;
        }
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::reduceTtl(pcpp::Packet* parsedPacket)
{
    if (this->reducesTtl()) {
        if(parsedPacket->isPacketOfType(pcpp::IPv4)) {
            auto ipLayer = parsedPacket->getLayerOfType<pcpp::IPv4Layer>();
            if (this->ttl < ipLayer->getIPv4Header()->timeToLive) {
                ipLayer->getIPv4Header()->timeToLive -= this->ttl;
                return parsedPacket;
            }
        }
        if(parsedPacket->isPacketOfType(pcpp::IPv6)) {
            auto ipLayer = parsedPacket->getLayerOfType<pcpp::IPv6Layer>();
            if (this->ttl < ipLayer->getIPv6Header()->hopLimit) {
                ipLayer->getIPv6Header()->hopLimit -= this->ttl;
                return parsedPacket;
            } 
        }
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::filterIcmp(pcpp::Packet* parsedPacket)
{
    if(!parsedPacket->isPacketOfType(pcpp::ICMP)) {
        return parsedPacket;
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::replaceDnsAddress(pcpp::Packet* parsedPacket)
{
    if (this->replacesDnsAddress()) {
        return parsedPacket;
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::replaceDnsPort(pcpp::Packet* parsedPacket)
{    
    if (this->replacesDnsPort()) {
        if(parsedPacket->isPacketOfType(pcpp::UDP) && parsedPacket->isPacketOfType(pcpp::DNS)) {
            // pcpp::DnsLayer* dnsLayer = parsedPacket->getLayerOfType<pcpp::DnsLayer>();
            return parsedPacket;
        }
    }
    return nullptr;
}
