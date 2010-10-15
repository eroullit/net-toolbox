INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/${NET-NG}/include)
ADD_LIBRARY(net-ng bpf.c cursor.c print.c ringbuff.c rx_ring_compat.c thread.c xmalloc.c dump.c netdev.c replay.c rx_ring.c strlcpy.c)
#ADD_LIBRARY(net-ng tx_ring.c)
