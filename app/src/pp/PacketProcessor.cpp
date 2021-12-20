#include "../../include/pp/PacketProcessor.h"

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
{
    this->vlanId = vlanId;
    this->ipVersion = ipVersion;
    this->ttl = ttl;
    this->dnsAddress = dnsAddress;
    this->dnsPort = dnsPort;
    this->reader = nullptr;
    this->writer = nullptr;
}

PacketProcessor::~PacketProcessor()
{
    if(this->reader != nullptr) {
        reader->close();
        delete reader;
    }   
    if(this->writer != nullptr) {
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

void PacketProcessor::setTTL(uint8_t ttl)
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

bool PacketProcessor::reducesTTL()
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
        pcpp::VlanLayer* vlanLayer = parsedPacket->getLayerOfType<pcpp::VlanLayer>();
        // vlanLayer->getVlanID();
        if (vlanLayer == NULL)
        {
            std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
        }
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
        if ((this->ipVersion == 4 && parsedPacket->isPacketOfType(pcpp::IPv4)) ||
            (this->ipVersion == 6 && parsedPacket->isPacketOfType(pcpp::IPv6))) {
              return parsedPacket;
        }
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::reduceTTL(pcpp::Packet* parsedPacket)
{
    if (this->reducesTTL()) {
        int packetTTL = 0;
        if(parsedPacket->isPacketOfType(pcpp::IPv4)) {
            pcpp::IPv4Layer* ipLayer = parsedPacket->getLayerOfType<pcpp::IPv4Layer>();
            packetTTL = ipLayer->getIPv4Header()->timeToLive;
            if (this->ttl < packetTTL) {
                ipLayer->getIPv4Header()->timeToLive = packetTTL - this->ttl;
                return parsedPacket;
            }
        }
        if(parsedPacket->isPacketOfType(pcpp::IPv6)) {
            pcpp::IPv6Layer* ipLayer = parsedPacket->getLayerOfType<pcpp::IPv6Layer>();
            packetTTL = ipLayer->getIPv6Header()->hopLimit;
            if (this->ttl < packetTTL) {
                ipLayer->getIPv6Header()->hopLimit = packetTTL - this->ttl;
                return parsedPacket;
            } 
        }
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::filterICMP(pcpp::Packet* parsedPacket)
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
        // reverse src and dst IP addresses
        // pcpp::IPLayer* ipLayer = parsedPacket->getLayerOfType<pcpp::IPLayer>();
        // pcpp::IPAddress srcIP = ipLayer->getSrcIPAddress();
        // pcpp::IPv4Layer* ip4Layer = dynamic_cast<pcpp::IPv4Layer*>(ipLayer);
        // pcpp::IPv6Layer* ip6Layer = dynamic_cast<pcpp::IPv6Layer*>(ipLayer);
        // if (ip4Layer != NULL)
        // {
        //   ip4Layer->setSrcIPv4Address(ip4Layer->getDstIPv4Address());
        //   ip4Layer->setDstIPv4Address(srcIP.getIPv4());
        //   ip4Layer->getIPv4Header()->ipId = 0;
        // }
        // else
        // {
        //   ip6Layer->setSrcIPv6Address(ip6Layer->getDstIPv6Address());
        //   ip6Layer->setDstIPv6Address(srcIP.getIPv6());
        // }

        // // reverse src and dst UDP ports
        // uint16_t srcPort = udpLayer->getUdpHeader()->portSrc;
        // udpLayer->getUdpHeader()->portSrc = udpLayer->getUdpHeader()->portDst;
        // udpLayer->getUdpHeader()->portDst = srcPort;

  
        if(parsedPacket->isPacketOfType(pcpp::UDP) && parsedPacket->isPacketOfType(pcpp::DNS)) {
            // pcpp::DnsLayer* dnsLayer = parsedPacket->getLayerOfType<pcpp::DnsLayer>();
            


            return parsedPacket;
        }
    }
    return nullptr;
}