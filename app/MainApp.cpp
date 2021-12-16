#include <iostream>
#include <getopt.h>

#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>

// #include "stdlib.h"
// #include "PcapFileDevice.h"
// #include "Packet.h"
// #include "EthLayer.h"
// #include "IPv4Layer.h"
// #include "TcpLayer.h"


#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

enum { def, vlan, ip_version, ttl, dns_addr, dns_port };

static struct option ArgOptions[] =
{
    {"input",      required_argument, 0, 'i'},
    {"output",     required_argument, 0, 'o'},
    {"vlan",       optional_argument, 0, vlan},
    {"ip-version", optional_argument, 0, ip_version},
    {"ttl",        optional_argument, 0, ttl},
    {"dns-addr",   optional_argument, 0, dns_addr},
    {"dns-addr",   optional_argument, 0, dns_port},
    {"help",       no_argument,       0, 'h'},
    {0, 0, 0, 0}
};

/**
 * Print application usage
 */
void printUsage()
{
    std::cout << std::endl
    << "Usage:" << std::endl
    << "------" << std::endl
    << "pcap-convert [-h] -i input -o output " << std::endl
    << std::endl
    << "Required parameters:" << std::endl
    << std::endl
    << "    -i: Path of the input pcap file" << std::endl
    << "    -o: Path of the input pcap file" << std::endl
    << std::endl
    << "Optional parameters:" << std::endl
    << std::endl
    << "    --vlan            : Drop packets that are not in the vlan id value specified" << std::endl
    << "    --ip-version      : Drop packets that are not in the same ip-version" << std::endl
    << "    --ttl             : Value to decrease the TTL of a packet that is not on IPv4 or IPv6" << std::endl
    << "    --dns-addr        : DNS address to be replaced in a UDP packet with DNS layer" << std::endl
    << "    --dns-port        : DNS port to be replaced in in a UDP packet with DNS layer" << std::endl
    << "    -h                : Displays this help message and exits" << std::endl
    << std::endl;
}

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::TCP:
        return "TCP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
    pcpp::AppName::init(argc, argv);
    //Get arguments from user for incoming interface and outgoing interface
    std::string inputFile = "", outputFile = "";
    int optionIndex = 0;
    int opt = 0;
    uint16_t vlan_id = 0;
    while((opt = getopt_long_only(argc, argv, "i:o:", ArgOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 'i':
                        // printf(optarg);
                inputFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            case vlan:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                    vlan_id = atoi(optarg);
                    printf(" %d", vlan_id);
                }
                break;
            case ip_version:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) { 

                }
                break;
            case ttl:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {

                }
                break;
            case dns_addr:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {

                }
                break;
            case dns_port:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {

                }
                break;
            case 'h':
                printUsage();
                exit(0);
                break;
            default:
                printUsage();
                exit(-1);
        }
    }

    PacketProcessor packetProcessor = new PacketProcessor();

    packetProcessor.initializeReader(inputFile);

    packetProcessor.initializeWriter(outputFile);

    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(input_file);

    pcpp::PcapFileWriterDevice pcapWriter(output_file, pcpp::LINKTYPE_ETHERNET);


    while (reader->getNextPacket(rawPacket)) {
          // parse the raw packet into a parsed packet
          pcpp::Packet parsedPacket(&rawPacket);

          pcpp::Packet* currentPacket = &parsedPacket;
          
          currentPacket = packetProcessor->FilterVlanId(currentPacket);
          currentPacket = packetProcessor->FilterNonEthernet(currentPacket);
          currentPacket = packetProcessor->FilterIpVersion(currentPacket);
          currentPacket = packetProcessor->ReduceTTL(currentPacket);
          currentPacket = packetProcessor->FilterICMP(currentPacket);
          
          pcapWriter.writePacket(currentPacket);          
    }

    delete packetProcessor;
}
