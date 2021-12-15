#include "include/PacketProcessor.h"

PacketProcessor::PacketProcessor()
{
        this->vlanId =     -1;
        this->ipVersion =  -1;
        this->ttl =        -1;
        this->dnsAddress = -1;
        this->dnsPort =    -1;
}

PacketProcessor::PacketProcessor(int vlanId, int ipVersion, int ttl, int dnsAddress, int dnsPort)
{
        this->vlanId =     vlanId;
        this->ipVersion =  ipVersion;
        this->ttl =        ttl;
        this->dnsAddress = dnsAddress;
        this->dnsPort =    dnsPort;
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

void PacketProcessor::InitializeReader(std::string inputFile)
{
        reader = pcpp::IFileReaderDevice::getReader(inputFile);
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
