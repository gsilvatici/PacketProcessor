#ifndef PACKETPROCESSORINITIALIZER_H_
#define PACKETPROCESSORINITIALIZER_H_

#include <iostream>
#include <getopt.h>

namespace pp
{
    enum { def, vlan, ipVersion, ttl, dnsAddr, dnsPort };

    static struct option ArgOptions[] =
    {
        {"input",      required_argument, 0, 'i'},
        {"output",     required_argument, 0, 'o'},
        {"vlan",       optional_argument, 0, vlan},
        {"ip-version", optional_argument, 0, ipVersion},
        {"ttl",        optional_argument, 0, ttl},
        {"dns-addr",   optional_argument, 0, dnsAddr},
        {"dns-addr",   optional_argument, 0, dnsPort},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    class PacketProcessorInitializer
    {
      public:
        void run(int argc, char **argv);
        void printUsage();
    };
}

#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

#endif // PACKETPROCESSORINITIALIZER_H_
