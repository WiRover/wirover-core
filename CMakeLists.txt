cmake_minimum_required(VERSION 2.6)

project(WIROVER)
set(WIROVER_VERSION_MAJOR 1)
set(WIROVER_VERSION_MINOR 0)

# Add -DNDEBUG for release versions to ignore assert()s
set(CMAKE_C_FLAGS "-g -Wall -pedantic -std=c99 -D_POSIX_C_SOURCE -DDEBUG_PRINT")

# Include the common header files
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${WIROVER_SOURCE_DIR}/common)

# Set the location of common source files
set(COMMON ${WIROVER_SOURCE_DIR}/common)

add_subdirectory(${WIROVER_SOURCE_DIR}/wiroot)
add_subdirectory(${WIROVER_SOURCE_DIR}/wigateway)
add_subdirectory(${WIROVER_SOURCE_DIR}/wicontroller)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wigateway/wigateway.conf ${CMAKE_CURRENT_BINARY_DIR}/wigateway.conf COPYONLY)
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wicontroller/wicontroller.conf ${CMAKE_CURRENT_BINARY_DIR}/wicontroller.conf COPYONLY)

