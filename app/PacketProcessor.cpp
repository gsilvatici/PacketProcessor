#include "include/PacketProcessor.h"

PacketProcessor::PacketProcessor()
{
    this->vlanId =     -1;
    this->ipVersion =  -1;
    this->ttl =        -1;
    this->dnsAddress = -1;
    this->dnsPort =    -1;
    this->reader =  nullptr;
    this->writer =  nullptr;
}

PacketProcessor::PacketProcessor(int vlanId, int ipVersion, int ttl, int dnsAddress, int dnsPort)
{
    this->vlanId =     vlanId;
    this->ipVersion =  ipVersion;
    this->ttl =        ttl;
    this->dnsAddress = dnsAddress;
    this->dnsPort =    dnsPort;
    this->reader =  nullptr;
    this->writer =  nullptr;
    }

PacketProcessor::~PacketProcessor()
{
    if(this->reader != nullptr) 
    {
        reader->close();
        delete reader;
    }
        
    if(this->writer != nullptr) 
    {
        writer->close();
        delete writer;
    }
}

bool PacketProcessor::FiltersByVLAN()
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
    if (reader != nullptr)
    {
        return reader->open();
    } else {
        return false;        
    }   
}

void PacketProcessor::InitializeWriter(std::string outputFile)
{
    writer = new pcpp::PcapFileWriterDevice(outputFile, pcpp::LINKTYPE_ETHERNET);
}

pcpp::IFileReaderDevice* PacketProcessor::getPacketReader()
{
    return this->reader;
}

pcpp::PcapFileWriterDevice* PacketProcessor::getPacketWriter()
{
    return this->writer;
}

pcpp::Packet* PacketProcessor::FilterNonEthernet(pcpp::Packet* parsedPacket)
{
    pcpp::Layer* curLayer = parsedPacket->getFirstLayer();

    // return parsedPacket;
    if (curLayer->getProtocol() != pcpp::Ethernet)
    {
        return nullptr;
    } else {
        return parsedPacket;
    }
}

pcpp::Packet* PacketProcessor::FilterByIpVersion(pcpp::Packet* parsedPacket)
{
    for (pcpp::Layer* curLayer = parsedPacket->getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
    {
        if (curLayer->getProtocol() == pcpp::Ethernet)
        {
                return nullptr;
        } else 
        {
                return parsedPacket;
        }
    }
    return parsedPacket;
}