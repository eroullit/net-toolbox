#Project name is not mandatory, but you should use it
PROJECT(nettools-ng C)

# States that CMake required version must be >= 2.6
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

FIND_PACKAGE(Threads REQUIRED)

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
# Activate this when you want to build a shared lib out the the lib/ directory
# Bear in mind that no profiling will be available on 64-bit arch when on
SET(BUILD_SHARED_LIBS ON)

ADD_DEFINITIONS(
	-W
	-Wall
	-Werror
	-pedantic
	-std=gnu99
	-O2
	-z relo
	-pie
	-fstack-protector
	-D_REENTRANT
	-D_FORTIFY_SOURCE=2
)

IF (CMAKE_BUILD_TYPE STREQUAL profile)
	ADD_DEFINITIONS(-g -pg)
ENDIF (CMAKE_BUILD_TYPE STREQUAL profile)

SET(CMAKE_C_FLAGS "-lm -lpthread")

SET(NET-NG "net-ng")
SET(NETSNIFF-NG "netsniff-ng")
SET(LIBHASHISH "hashish")

ENABLE_TESTING()

LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/${NET-NG})
ADD_SUBDIRECTORY(${LIBHASHISH})
ADD_SUBDIRECTORY(${NET-NG})
ADD_SUBDIRECTORY(${NETSNIFF-NG})
