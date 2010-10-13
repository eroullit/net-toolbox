# Project name is not mandatory, but you should use it
PROJECT(nettools-ng C)

# States that CMake required version must be >= 2.6
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
# Activate this when you want to build a shared lib out the the lib/ directory
# Bear in mind that no profiling will be available on 64-bit arch when on
SET(BUILD_SHARED_LIBS ON)

#SET(CMAKE_C_FLAGS "-Wall -Werror -pedantic -std=gnu99 -O2 -lrt -lpthread")
#SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g")
#SET(CMAKE_C_FLAGS_PROFILE "${CMAKE_C_FLAGS} -pg")

SET(NET-NG "net-ng")
#SET(NETSNIFF-NG "netsniff-ng")

ADD_SUBDIRECTORY(net-ng)
ADD_SUBDIRECTORY(netsniff-ng)

