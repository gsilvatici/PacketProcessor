#include "pp/PacketProcessorInitializer.h"

using namespace pp;

int main(int argc, char **argv)
{
    std::cout << "ARGC";
    
    std::cout << argc;
    std::cout << "ARGV";
  
    std::cout << argv;
    PacketProcessorInitializer initializer;
    initializer.run(argc, argv);
    return 0;
}
