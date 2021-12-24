cmake_minimum_required(VERSION 3.10)

project(pcap-convert)

set(CMAKE_CXX_COMPILER g++)

file(GLOB_RECURSE sources_pp app/src/pp/*.cpp  app/include/pp/*.h)
file(GLOB_RECURSE sources app/src/main.cpp app/src/pp/*.cpp  app/include/pp/*.h)
file(GLOB_RECURSE sources_test test/src/*.cpp)

add_executable(pcap-convert ${sources})

target_link_libraries(${PROJECT_NAME} libPcap++.a libPacket++.a libCommon++.a libpcap.a)

target_compile_options(pcap-convert PUBLIC -std=c++17 -Wall)

target_include_directories(pcap-convert PUBLIC app/include /usr/local/include/pcapplusplus)

find_package(GTest)

if(GTEST_FOUND)
  add_executable(unit_tests ${sources_test} ${sources_pp})

  # we add this define to prevent collision with the main
  # this might be better solved by not adding the source with the main to the
  # testing target
  # target_compile_definitions(unit_tests PUBLIC TESTING)

  target_compile_options(unit_tests PUBLIC -static-libstdc++ -std=c++17 -I h -pthread -Wall)

  target_include_directories(unit_tests PUBLIC app/include /usr/local/include/pcapplusplus)

  set_target_properties(unit_tests PROPERTIES LINK_SEARCH_START_STATIC 1)
  set_target_properties(unit_tests PROPERTIES LINK_SEARCH_END_STATIC 1)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

  target_link_libraries(${PROJECT_NAME} libPcap++.a libPacket++.a libCommon++.a libpcap.a pthread.a)

  # this allows us to use our executable as a link library
  # therefore we can inherit all compiler options and library dependencies
  # set_target_properties(pcap-convert PROPERTIES ENABLE_EXPORTS on)

  target_link_libraries(unit_tests PUBLIC
    ${GTEST_BOTH_LIBRARIES} libPcap++.a libPacket++.a libCommon++.a libpcap.a libpthread.a
    # pcap-convert
  )
endif()