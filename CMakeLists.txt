cmake_minimum_required(VERSION 3.10)

project(pcap-convert)

file(GLOB_RECURSE sources      app/src/main.cpp app/src/pp/*.cpp  app/include/pp/*.h)
file(GLOB_RECURSE sources_test test/src/*.cpp)

add_executable(pcap-convert ${sources})
# libCommon++.a libPacket++.a libPcap++.a
# -lPcap++ -lPacket++ -lCommon++ -lpcap
target_link_libraries(${PROJECT_NAME} libPcap++.a libPacket++.a libCommon++.a libpcap.a)

target_compile_options(pcap-convert PUBLIC -std=c++17 -Wall)

target_include_directories(pcap-convert PUBLIC app/include /usr/local/include/pcapplusplus)
