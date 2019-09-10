cmake_minimum_required (VERSION 2.6)
project (psdpi)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

add_executable(psdpi psdpi.c hash.c crc_32.c ps_eth.c ps_ip.c l3l4.c ps_stats.c tpool.c )
target_link_libraries(psdpi pcap zmq pthread config)

add_executable(client zmqclient.c)
target_link_libraries(client zmq config)