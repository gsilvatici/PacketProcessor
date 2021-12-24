#include <getopt.h>

#include "pp/PacketProcessor.h"
#include "pp/PacketProcessorInitializer.h"

using namespace pp;
using namespace std;

void PacketProcessorInitializer::run(int argc, char **argv)
{
    string inputFile = "", outputFile = "";
    int optionIndex = 0;
    int opt = 0;
    unique_ptr<PacketProcessor> packetProcessor(new PacketProcessor());
    while((opt = getopt_long_only(argc, argv, "i:o:", ArgOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 'i':
                inputFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            case vlan:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                    packetProcessor->setVlanId(atoi(optarg));
                }
                break;
            case ipVersion:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                    packetProcessor->setIpVersion(atoi(optarg));
                }
                break;
            case ttl:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                    packetProcessor->setTtl(atoi(optarg));
                }
                break;
            case dnsAddr:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                    // packetProcessor->setDnsAddress(atoi(optarg));
                }
                break;
            case dnsPort:
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                    packetProcessor->setDnsPort(atoi(optarg));
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
    packetProcessor->processFile(inputFile, outputFile);
}

void PacketProcessorInitializer::printUsage()
{
    cout << endl
    << "Usage:" << endl
    << "------" << endl
    << "pcap-convert [-h] -i input -o output " << endl
    << endl
    << "Required parameters:" << endl
    << endl
    << "    -i: Path of the input pcap file" << endl
    << "    -o: Path of the input pcap file" << endl
    << endl
    << "Optional parameters:" << endl
    << endl
    << "    --vlan            : Drop packets that are not in the vlan id value specified" << endl
    << "    --ip-version      : Drop packets that are not in the same ip-version" << endl
    << "    --ttl             : Value to decrease the TTL of a packet that is not on IPv4 or IPv6" << endl
    << "    --dns-addr        : DNS address to be replaced in a UDP packet with DNS layer" << endl
    << "    --dns-port        : DNS port to be replaced in in a UDP packet with DNS layer" << endl
    << "    -h                : Displays this help message and exits" << endl
    << endl;
}

