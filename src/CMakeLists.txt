cmake_minimum_required(VERSION 2.6)

project(WIROVER)

# Add -DNDEBUG for release versions to ignore assert()s
set(CMAKE_C_FLAGS "-g -rdynamic -Wall -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L -DDEBUG_PRINT")

# Include the common header files
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${WIROVER_SOURCE_DIR}/common)

# Set the location of common source files
set(COMMON ${WIROVER_SOURCE_DIR}/common)

add_subdirectory(${WIROVER_SOURCE_DIR}/wiroot)
add_subdirectory(${WIROVER_SOURCE_DIR}/wigateway)
add_subdirectory(${WIROVER_SOURCE_DIR}/wicontroller)

set(NODE_ID_PATH "/etc/wirover.d/node_id" CACHE STRING "Location of node ID file")
set(PUBLIC_KEY_PATH "/etc/wirover.d/node.pub" CACHE STRING "Location of node public key")
set(WIROVER_VAR_DIR "/var/lib/wirover" CACHE STRING "Directory containing runtime state files")
set(INTERFACE_LIST_FILE "/var/lib/wirover/ife_list" CACHE STRING "Location of interface list file")
set(FLOW_TABLE_FILE "/var/lib/wirover/flow_table" CACHE STRING "Location of flow table file")
set(SYSTEM_STATE_FILE "/var/lib/wirover/state" CACHE STRING "Location of system state file")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

