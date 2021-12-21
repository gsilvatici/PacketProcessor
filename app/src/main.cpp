#include "/pp/PacketProcessor.h"


int main(int argc, char **argv)
{
  PacketProcessorInitializer initializer;
  initializer.run(argc, argv);
  return 0;
}