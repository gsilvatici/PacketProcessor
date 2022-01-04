#include "pp/PacketProcessor.h"

using namespace std;
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

void PacketProcessor::setDnsAddress(const IPAddress &dnsAddress)
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

bool PacketProcessor::initializeReader(const string inputFile)
{
    reader.reset(IFileReaderDevice::getReader(inputFile));
    if (reader) {
        return reader->open();
    }
    return false; 
}

bool PacketProcessor::initializeWriter(const string outputFile)
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
        if (vlanLayer && this->vlanId != vlanLayer->getVlanID()) {
              return nullptr;
        }
    }
    return parsedPacket;
}

Packet* PacketProcessor::filterNonEthernet(Packet* parsedPacket)
{
    if(!parsedPacket->isPacketOfType(Ethernet)) {
        return nullptr;
    }
    return parsedPacket;
}

Packet* PacketProcessor::filterIpVersion(Packet* parsedPacket)
{
    if (this->filtersIpVersion()) {
        switch(this->ipVersion)
        {
            case 4:
                if(!parsedPacket->isPacketOfType(IPv4))
                    return nullptr;
            break;

            case 6:
                if(!parsedPacket->isPacketOfType(IPv6))
                    return nullptr;
            break;
        }
    }
    return parsedPacket;
}

Packet* PacketProcessor::reduceTtl(Packet* parsedPacket)
{
	  if (!parsedPacket->isPacketOfType(IP))
		    return parsedPacket;

    if (this->reducesTtl()) {
        auto ipLayer = parsedPacket->getLayerOfType<IPLayer>();
        auto ip4Layer = dynamic_cast<IPv4Layer*>(ipLayer);
        auto ip6Layer = dynamic_cast<IPv6Layer*>(ipLayer);

        if(ip4Layer) {
            if (this->ttl < ip4Layer->getIPv4Header()->timeToLive) {
                ip4Layer->getIPv4Header()->timeToLive -= this->ttl;
                // int aux = ip4Layer->getIPv4Header()->timeToLive;
                // printf(" %d ", aux);
            } else {
              return nullptr;
            }
        }
        if(ip6Layer) {
            if (this->ttl < ip6Layer->getIPv6Header()->hopLimit) {
                ip6Layer->getIPv6Header()->hopLimit -= this->ttl;
            } else {
              return nullptr;
            }
        }
    }
    return parsedPacket;
}

Packet* PacketProcessor::filterIcmp(Packet* parsedPacket)
{
    if(parsedPacket->isPacketOfType(ICMP)) {
        return nullptr;
    }
    return parsedPacket;
}

Packet* PacketProcessor::replaceDnsAddress(Packet* parsedPacket)
{
	  if (!parsedPacket->isPacketOfType(DNS) || !parsedPacket->isPacketOfType(IP) ||
        !parsedPacket->isPacketOfType(UDP) || !parsedPacket->isPacketOfType(Ethernet))
		    return parsedPacket;

    if (replacesDnsAddress()) {
        auto ipLayer = parsedPacket->getLayerOfType<IPLayer>();
        auto dnsLayer = parsedPacket->getLayerOfType<DnsLayer>();

        IPv4Layer* ip4Layer = dynamic_cast<IPv4Layer*>(ipLayer);
        IPv6Layer* ip6Layer = dynamic_cast<IPv6Layer*>(ipLayer);
        
        switch(dnsLayer->getDnsHeader()->queryOrResponse) {
            // request
            case 0:
                if (ip4Layer && dnsAddress.isIPv4()) {
                    ip4Layer->setDstIPv4Address(this->dnsAddress.getIPv4());
                } else if (ip6Layer && this->dnsAddress.isIPv6()) {
                    ip6Layer->setDstIPv6Address(this->dnsAddress.getIPv6());
                } 
                break;
            // response
            case 1:
                if (ip4Layer && this->dnsAddress.isIPv4()) {
                    ip4Layer->setSrcIPv4Address(this->dnsAddress.getIPv4());
                } else if (ip6Layer && this->dnsAddress.isIPv6()) {
                    ip6Layer->setSrcIPv6Address(this->dnsAddress.getIPv6());
                } 
                break;
        }
    }
    return parsedPacket;
}

Packet* PacketProcessor::replaceDnsPort(Packet* parsedPacket)
{    
	  if (!parsedPacket->isPacketOfType(DNS) || !parsedPacket->isPacketOfType(IP) ||
        !parsedPacket->isPacketOfType(UDP) || !parsedPacket->isPacketOfType(Ethernet))
		    return parsedPacket;

    if (replacesDnsPort()) {
        auto udpLayer = parsedPacket->getLayerOfType<UdpLayer>();
        auto dnsLayer = parsedPacket->getLayerOfType<DnsLayer>();
        
        switch(dnsLayer->getDnsHeader()->queryOrResponse) {
            // request
            case 0:
                udpLayer->getUdpHeader()->portDst = this->dnsPort; 
                break;
            // response
            case 1:
                udpLayer->getUdpHeader()->portSrc = this->dnsPort;
                break;
        }
    }
    return parsedPacket;
}

Packet* PacketProcessor::processPacket(Packet* parsedPacket)
{   
    // If any filter drop the packet return a droped packet
    if (!filterVlanId(parsedPacket) || !filterNonEthernet(parsedPacket)
        || !filterIpVersion(parsedPacket) || !filterIcmp(parsedPacket))
          return nullptr;

    reduceTtl(parsedPacket);
    replaceDnsAddress(parsedPacket);
    replaceDnsPort(parsedPacket);

    return parsedPacket;
    // return replaceDnsAddress(parsedPacket);
}

int PacketProcessor::processFile(const string inputFile, const string outputFile)
{
    if (!initializeReader(inputFile)) {
      cerr << "Cannot open " + inputFile + "file for reading" << endl;
      return 1;
    }

    if (!initializeWriter(outputFile)) {
      cerr << "Cannot open " + outputFile + "file for writing" << endl;
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
