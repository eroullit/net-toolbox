PROJECT(netcore-ng C)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/${PROJECT_NAME}/include)

ADD_LIBRARY(${PROJECT_NAME} 	packet_mmap.c
				nic.c
				time.c
				rx_ring.c
)

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${LIBS})
