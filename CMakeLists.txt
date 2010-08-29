cmake_minimum_required(VERSION 2.6)

project(WIROVER)
set(WIROVER_VERSION_MAJOR 0)
set(WIROVER_VERSION_MINOR 0)

# Add -DNDEBUG for release versions to ignore assert()s
set(CMAKE_C_FLAGS "-g -Wall -pedantic -std=c99 -D_POSIX_C_SOURCE")

# Include the common header files
include_directories(${WIROVER_SOURCE_DIR}/common)

# Set the location of common source files
set(COMMON ${WIROVER_SOURCE_DIR}/common)

# Build wiroot
add_subdirectory(${WIROVER_SOURCE_DIR}/wiroot)


