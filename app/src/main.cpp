#include "pp/PacketProcessorInitializer.h"

using namespace pp;

int main(int argc, char **argv)
{
    PacketProcessorInitializer initializer;
    initializer.run(argc, argv);
    return 0;
}