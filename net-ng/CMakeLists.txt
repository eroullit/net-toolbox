INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/${NET-NG}/include)
ADD_SUBDIRECTORY(${CMAKE_SOURCE_DIR}/${NET-NG}/tests)
ADD_LIBRARY(net-ng bpf.c cursor.c print.c rx_ring_compat.c thread.c xmalloc.c netdev.c pcap.c rx_ring.c strlcpy.c hash.c system.c)
#ADD_LIBRARY(net-ng tx_ring.c)
