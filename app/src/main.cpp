#include "pp/PacketProcessorInitializer.h"

using namespace pp;

#ifndef TESTING
int main(int argc, char **argv)
{
    PacketProcessorInitializer initializer;
    initializer.run(argc, argv);
    return 0;
}
#endif
