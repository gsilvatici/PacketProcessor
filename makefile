include /usr/local/etc/PcapPlusPlus.mk

CXX = g++
CXXFLAGS = $(PCAPPP_INCLUDES) $(PCAPPP_LIBS_DIR) -std=c++17 -Wall -I h -I /usr/local/include/gtest/ -c
LXXFLAGS = $(PCAPPP_LIBS_DIR) -static-libstdc++ -std=c++17 -I h -pthread
OBJECTS = ./obj/PacketProcessor.o ./obj/PacketProcessorTest.o
GTEST = /usr/local/lib/libgtest.a
TESTN = test/test_app

all: test

test: $(OBJECTS)
	$(CXX) $(LXXFLAGS) -o $(TESTN) $(OBJECTS) $(GTEST) $(PCAPPP_LIBS)
./obj/PacketProcessor.o: ./app/PacketProcessor.cpp
	$(CXX) $(CXXFLAGS) ./app/PacketProcessor.cpp -o ./obj/PacketProcessor.o
./obj/PacketProcessorTest.o: ./test/PacketProcessorTest.cpp
	$(CXX) $(CXXFLAGS) ./test/PacketProcessorTest.cpp -o ./obj/PacketProcessorTest.o
clean:
	rm -fv $(TESTN) $(OBJECTS)