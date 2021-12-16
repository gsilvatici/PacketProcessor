#include "include/PacketProcessor.h"

PacketProcessor::PacketProcessor()
{
    this->vlanId =     -1;
    this->ipVersion =  -1;
    this->ttl =        -1;
    this->dnsAddress = -1;
    this->dnsPort =    -1;
    this->reader =     nullptr;
    this->writer =     nullptr;
}

PacketProcessor::PacketProcessor(int vlanId, int ipVersion, int ttl, int dnsAddress, int dnsPort)
{
    this->vlanId =     vlanId;
    this->ipVersion =  ipVersion;
    this->ttl =        ttl;
    this->dnsAddress = dnsAddress;
    this->dnsPort =    dnsPort;
    this->reader =     nullptr;
    this->writer =     nullptr;
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

void PacketProcessor::setVlanId(int vlanId)
{
    this->vlanId = vlanId;
}

void PacketProcessor::setIpVersion(int ipVersion)
{
    this->ipVersion = ipVersion;
}

void PacketProcessor::setTTL(int ttl)
{
    this->ttl = ttl;
}

void PacketProcessor::setDnsAddress(int dnsAddress)
{
    this->dnsAddress = dnsAddress;
}

void PacketProcessor::setDnsPort(int dnsPort)
{
    this->dnsPort = dnsPort;
}

bool PacketProcessor::FiltersVLAN()
{
    return this->vlanId == -1 ? false : true;
}

bool PacketProcessor::FiltersIpVersion()
{
    return this->ipVersion == -1 ? false : true;
}

bool PacketProcessor::ReducesTTL()
{
    return this->ttl == -1 ? false : true;
}

bool PacketProcessor::ReplacesDnsAddress()
{
    return this->dnsAddress == -1 ? false : true;
}

bool PacketProcessor::ReplacesDnsPort()
{
    return this->dnsPort == -1 ? false : true;
}

bool PacketProcessor::InitializeReader(std::string inputFile)
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

bool PacketProcessor::InitializeWriter(std::string outputFile)
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

pcpp::Packet* PacketProcessor::FilterVlanId(pcpp::Packet* parsedPacket)
{
    if (this->FiltersVLAN()) {
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

pcpp::Packet* PacketProcessor::FilterNonEthernet(pcpp::Packet* parsedPacket)
{
    if(parsedPacket->isPacketOfType(pcpp::Ethernet)) {
        return parsedPacket;
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::FilterIpVersion(pcpp::Packet* parsedPacket)
{
    if (this->FiltersIpVersion()) {
        if ((this->ipVersion == 4 && parsedPacket->isPacketOfType(pcpp::IPv4)) ||
            (this->ipVersion == 6 && parsedPacket->isPacketOfType(pcpp::IPv6))) {
              return parsedPacket;
        }
    }
    return nullptr;
}

pcpp::Packet* PacketProcessor::ReduceTTL(pcpp::Packet* parsedPacket)
{
    if (this->ReducesTTL()) {
        pcpp::IPv4Layer* ipLayer = parsedPacket->getLayerOfType<pcpp::IPv4Layer>();
        int packetTTL = ipLayer->getIPv4Header()->timeToLive;
        // if (this->ttl > packetTTL) {
              ipLayer->getIPv4Header()->timeToLive = packetTTL - this->ttl;
              return parsedPacket;
        // }
    }
    return nullptr;
}