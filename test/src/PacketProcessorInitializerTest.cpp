#include "gtest/gtest.h"

#include "pp/PacketProcessorInitializer.h"

using namespace std;
using namespace pp;

TEST(RunInitializer, DISABLED_WithMultiplePacketsFileAndProposedCommandLine)
{
    uint8_t argc = 15;
    char* argv[] = {
      const_cast<char*> ("./pcap-convert"),
      const_cast<char*> ("--vlan"), const_cast<char*> ("5"),
      const_cast<char*> ("-ip-version"), const_cast<char*> ("4"),
      const_cast<char*> ("--ttl"), const_cast<char*> ("2"),
      const_cast<char*> ("--dns-addr"), const_cast<char*> ("10.0.0.1"),
      const_cast<char*> ("--dns-port"), const_cast<char*> ("5353"),
      const_cast<char*> ("-i"), const_cast<char*> ("input.pcapng"),
      const_cast<char*> ("-o"), const_cast<char*> ("output.pcap")
    };

    PacketProcessorInitializer initializer;
    initializer.run(argc, argv);
}
