#include "pp/PacketProcessorInitializer.h"

using namespace pp;

void PacketProcessorInitializer::run(int argc, char **argv)
{
    std::string inputFile = "", outputFile = "";
    int optionIndex = 0;
    int opt = 0;
    uint16_t vlan_id = 0;
    std::cout << "...";
    // while((opt = getopt_long_only(argc, argv, "i:o:", ArgOptions, &optionIndex)) != -1)
    // {
    //     switch (opt)
    //     {
    //         case 0:
    //             break;
    //         case 'i':
    //             // printf(optarg);
    //             inputFile = optarg;
    //             break;
    //         case 'o':
    //             outputFile = optarg;
    //             break;
    //         case vlan:
    //             if (OPTIONAL_ARGUMENT_IS_PRESENT) {
    //                 vlanId = atoi(optarg);
    //                 // printf(" %d", vlan_id);
    //             }
    //             break;
    //         case ip_version:
    //             if (OPTIONAL_ARGUMENT_IS_PRESENT) { 
    //                 // ipVersion = atoi(optarg);
    //             }
    //             break;
    //         case ttl:
    //             if (OPTIONAL_ARGUMENT_IS_PRESENT) {
    //                 // ttl = atoi(optarg);
    //             }
    //             break;
    //         case dns_addr:
    //             if (OPTIONAL_ARGUMENT_IS_PRESENT) {
    //                 // dnsAddress = atoi(optarg);
    //             }
    //             break;
    //         case dns_port:
    //             if (OPTIONAL_ARGUMENT_IS_PRESENT) {
    //                 // dnPort = atoi(optarg);
    //             }
    //             break;
    //         case 'h':
    //             printUsage();
    //             exit(0);
    //             break;
    //         default:
    //             printUsage();
    //             exit(-1);
    //     }
    // }

}
