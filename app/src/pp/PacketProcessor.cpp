#include "pp/PacketProcessor.h"

using namespace pp;
using namespace pcpp;

PacketProcessor::PacketProcessor()
{
    filters.reset(new bool[5] {false, false, false, false, false});
}

PacketProcessor::PacketProcessor(const uint16_t vlanId, const uint8_t ipVersion, const uint8_t ttl, const IPAddress &dnsAddress, const uint16_t dnsPort)
    : vlanId(vlanId), ipVersion(ipVersion), ttl(ttl), dnsAddress(dnsAddress), dnsPort(dnsPort), reader(nullptr), writer(nullptr)
{
    filters.reset(new bool[5] {true, true, true, true, true});
}

PacketProcessor::~PacketProcessor()
{
    if(reader)
        reader->close();

    if(writer) 
        writer->close();
}

void PacketProcessor::setVlanId(const uint16_t vlanId)
{
    this->vlanId = vlanId;
    filters[0] = true;
}

void PacketProcessor::setIpVersion(const uint8_t ipVersion)
{
    this->ipVersion = ipVersion;
    filters[1] = true;
}

void PacketProcessor::setTtl(const uint8_t ttl)
{
    this->ttl = ttl;
    filters[2] = true;
}

void PacketProcessor::setDnsAddress(const pcpp::IPAddress &dnsAddress)
{
    this->dnsAddress = dnsAddress;
    filters[3] = true;
}

void PacketProcessor::setDnsPort(const uint16_t dnsPort)
{
    this->dnsPort = dnsPort;
    filters[4] = true;
}

bool PacketProcessor::filtersVLAN()
{
    return filters[0];
}

bool PacketProcessor::filtersIpVersion()
{
    return filters[1];
}

bool PacketProcessor::reducesTtl()
{
    return filters[2];
}

bool PacketProcessor::replacesDnsAddress()
{
    return filters[3];
}

bool PacketProcessor::replacesDnsPort()
{
    return filters[4];
}

bool PacketProcessor::initializeReader(const std::string inputFile)
{
    reader.reset(IFileReaderDevice::getReader(inputFile));
    if (reader) {
        return reader->open();
    }
    return false; 
}

bool PacketProcessor::initializeWriter(const std::string outputFile)
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
        if (!vlanLayer) {
            std::cerr << "Something went wrong, couldn't find VLAN id" << std::endl;
        }
        if (this->vlanId == vlanLayer->getVlanID()) {
              return parsedPacket;
        }
        return nullptr;
    }
    return parsedPacket;
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
        }
        return nullptr;
    }
    return parsedPacket;
}

Packet* PacketProcessor::reduceTtl(Packet* parsedPacket)
{
    if (this->reducesTtl()) {
        if(parsedPacket->isPacketOfType(IPv4)) {
            auto ipLayer = parsedPacket->getLayerOfType<IPv4Layer>();
            if (this->ttl < ipLayer->getIPv4Header()->timeToLive) {
                ipLayer->getIPv4Header()->timeToLive -= this->ttl;
                int aux = ipLayer->getIPv4Header()->timeToLive;
                printf(" %d ", aux);
                // std::cout << ipLayer->getIPv4Header()->timeToLive;
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
    if (replacesDnsAddress()) {

      	// extract all packet layers
        auto ipLayer = parsedPacket->getLayerOfType<pcpp::IPLayer>();
        auto udpLayer = parsedPacket->getLayerOfType<pcpp::UdpLayer>();
        auto dnsLayer = parsedPacket->getLayerOfType<pcpp::DnsLayer>();

        // skip DNS requests with more than 1 request or with 0 requests
        // if (dnsLayer->getDnsHeader()->numberOfQuestions != pcpp::hostToNet16(1) || dnsLayer->getFirstQuery() == NULL)
        //    return;


        pcpp::IPAddress srcIP = ipLayer->getSrcIPAddress();
        pcpp::IPv4Layer* ip4Layer = dynamic_cast<pcpp::IPv4Layer*>(ipLayer);
        pcpp::IPv6Layer* ip6Layer = dynamic_cast<pcpp::IPv6Layer*>(ipLayer);
        
        if (ip4Layer) {
          ip4Layer->setSrcIPv4Address();
          ip4Layer->setDstIPv4Address();
        } else {
          ip6Layer->setSrcIPv6Address();
          ip6Layer->setDstIPv6Address();
        }

        return parsedPacket;
    }
    return nullptr;
}

Packet* PacketProcessor::replaceDnsPort(Packet* parsedPacket)
{    
    if (replacesDnsPort()) {
        if(parsedPacket->isPacketOfType(UDP) && parsedPacket->isPacketOfType(DNS)) {
            // DnsLayer* dnsLayer = parsedPacket->getLayerOfType<DnsLayer>();
            return parsedPacket;
        }
    }
    return nullptr;
}

Packet* PacketProcessor::processPacket(Packet* parsedPacket)
{   
    // If any filter drop the packet return a droped packet
    if (!filterVlanId(parsedPacket) || !filterNonEthernet(parsedPacket)
        || !filterIpVersion(parsedPacket) || !filterIcmp(parsedPacket))
          return nullptr;

    return reduceTtl(parsedPacket);
}

int PacketProcessor::processFile(const std::string inputFile, const std::string outputFile)
{
    if (!initializeReader(inputFile)) {
      std::cerr << "Cannot open " + inputFile + "file for reading" << std::endl;
      return 1;
    }

    if (!initializeWriter(outputFile)) {
      std::cerr << "Cannot open " + outputFile + "file for writing" << std::endl;
      return 1;
    }

    RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket))
    {
          Packet parsedPacket(&rawPacket);

          Packet* processedPacket = &parsedPacket;
          
          processedPacket = processPacket(processedPacket);

          if (processedPacket)   
              writer->writePacket(*(processedPacket->getRawPacket()));       
    }
    return 0;
}
