#Project name is not mandatory, but you should use it
PROJECT(nettools-ng C)

# States that CMake required version must be >= 2.6
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
# Activate this when you want to build a shared lib out the the lib/ directory
# Bear in mind that no profiling will be available on 64-bit arch when on
SET(BUILD_SHARED_LIBS ON)

#FIND_PACKAGE(FLEX REQUIRED)
#FIND_PACKAGE(BISON REQUIRED)
FIND_PACKAGE(Threads REQUIRED)
IF(CMAKE_HAVE_PTHREAD_CREATE)
	SET(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})
ELSE(CMAKE_HAVE_PTHREAD_CREATE)
	MESSAGE(FATAL_ERROR "The framework only supports pthread")
ENDIF(CMAKE_HAVE_PTHREAD_CREATE)

FIND_PACKAGE(Doxygen)

IF(DOXYGEN_FOUND)
	CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
	ADD_CUSTOM_TARGET(doc ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
ENDIF(DOXYGEN_FOUND)

INCLUDE(CheckBPF)
INCLUDE(CheckPFPacket)
INCLUDE(CheckStrictAlign)
INCLUDE(CheckTxRing)

ADD_DEFINITIONS(
	-W
	-Wextra
	-Wall
	-Werror
	-pedantic
	-pedantic-errors
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

SET(CMAKE_C_FLAGS "-lm")

SET(NET-NG "netcore-ng")
SET(NETSNIFF-NG "netsniff-ng")
SET(LIBHASHISH "hashish")

ENABLE_TESTING()

LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/${NET-NG})
ADD_SUBDIRECTORY(${LIBHASHISH})
ADD_SUBDIRECTORY(${NET-NG})
ADD_SUBDIRECTORY(${NETSNIFF-NG})
