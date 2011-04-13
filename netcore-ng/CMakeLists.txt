PROJECT(netcore-ng C)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/${NET-NG}/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/${LIBHASHISH}/include)
ADD_SUBDIRECTORY(${CMAKE_SOURCE_DIR}/${NET-NG}/tests)

IF(DOXYGEN_FOUND)
	CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
	ADD_CUSTOM_TARGET(doc ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
ENDIF(DOXYGEN_FOUND)

ADD_LIBRARY(netcore-ng 	init.c
			bpf.c 
			cursor.c 
			thread.c 
			xmalloc.c 
			packet.c 
			netdev.c 
			pcap.c 
			rx_ring_compat.c 
			job.c 
			strlcpy.c 
			system.c 
			oui_hash.c 
			tcp_ports_hash.c 
			udp_ports_hash.c 
			ether_types_hash.c 
			dissector/raw.c 
			dissector/ethernet/dissector.c 
			dissector/ethernet/ethernet.c 
			dissector/ethernet/arp.c 
			dissector/ethernet/ip.c 
			dissector/ethernet/tcp.c 
			dissector/ethernet/icmp.c
)

TARGET_LINK_LIBRARIES(${NET-NG} ${LIBHASHISH} ${LIBS})
#ADD_LIBRARY(netcore-ng tx_ring.c)
