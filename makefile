include /usr/local/etc/PcapPlusPlus.mk

CXX = g++
CXXFLAGS = $(PCAPPP_INCLUDES) $(PCAPPP_LIBS_DIR) -std=c++17 -Wall -I h -I /usr/local/include/gtest/ -c
LXXFLAGS = $(PCAPPP_LIBS_DIR) -static-libstdc++ -std=c++17 -I h -pthread
OBJECTS = ./build/PacketProcessor.o ./build/PacketProcessorTest.o
GTEST = /usr/local/lib/libgtest.a
TESTN = build/test_app

all: test

test: $(OBJECTS)
	$(CXX) $(LXXFLAGS) -o $(TESTN) $(OBJECTS) $(GTEST) $(PCAPPP_LIBS)
./build/PacketProcessor.o: ./app/src/pp/PacketProcessor.cpp
	$(CXX) $(CXXFLAGS) ./app/src/pp/PacketProcessor.cpp -o ./build/PacketProcessor.o
./build/PacketProcessorTest.o: ./test/src/PacketProcessorTest.cpp
	$(CXX) $(CXXFLAGS) ./test/src/PacketProcessorTest.cpp -o ./build/PacketProcessorTest.o
clean:
	rm -fv $(TESTN) $(OBJECTS)