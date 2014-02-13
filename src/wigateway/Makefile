#
# Makefile for WiRover gateway
#
# Compiling with -rdynamic adds some extra symbols that the program can print
# out during a stack trace in response to a segfault.

CC=gcc
BINARY=wigateway

#
# Allow command arguments to override default setting.
override CFLAGS += -g -D GATEWAY -dH -rdynamic -std=gnu99 -Wall -pedantic -fstrict-aliasing
override LINK_FLAGS +=-lssl -lpthread -lm -lrt -lpcap -lcrypto -pthread

#
# Link against libgps.so if CONFIG_USE_GPSD is set.
ifneq (,$(findstring CONFIG_USE_GPSD, $(CFLAGS)))
    override LINK_FLAGS += -lgps
endif

#
# WiRover gateway code
GATEWAY_HEADERS := \
	gpsHandler.h \
	pcapSniff.h \
	scan.h \
	selectInterface.h

GATEWAY_OBJS := \
	main.o \
	active_bw.o \
	algoPerConnWrr.o \
	contChan.o \
	gpsHandler.o \
	interface.o \
	netlink.o \
	pcapSniff.o \
	scan.o \
	selectInterface.o \
	udp_ping.o

#
# Common library files for WiRover gateway code.
COMMON_HEADER := \
	active_bw.h \
	contChan.h \
	debug.h \
	evdo_buffer.h \
	handleTransfer.h \
	interface.h \
	link.h \
	link_priority.h \
	myssl.h \
	packet_debug.h \
	parameters.h \
	passive_bw.h \
	reOrderPackets.h \
	sockets.h \
	special.h \
	time_utils.h \
	tunnelInterface.h \
	udp_ping.h \
	utils.h

COMMON_OBJS := \
	debug.o \
	handleTransfer.o \
	link.o \
	link_priority.o \
	myssl.o \
	packet_debug.o \
	passive_bw.o \
	reOrderPackets.o \
	sockets.o \
	special.o \
	time_utils.o \
	tunnelInterface.o \
	utils.o


#
# Setup directory path and all object names.
COMMON_DIR := ../common/
COMMON_HEADERS := $(addprefix $(COMMON_DIR), $(COMMON_HEADER))
ALL_OBJS := $(COMMON_OBJS) $(GATEWAY_OBJS)

#
# Rules for final executable
.PHONY: all
all: $(ALL_OBJS)
	$(CC) -g -rdynamic -o $(BINARY) $(ALL_OBJS) $(LINK_FLAGS) 

#
# Rules for all objects, using static pattern rules (4.12).
# Output in current directory; do not pollute the common.
$(GATEWAY_OBJS): %.o: %.c $(GATEWAY_HEADERS) $(COMMON_HEADERS)
	$(CC) $(CFLAGS) -c $(subst .o,.c,$@)

$(COMMON_OBJS): %.o: $(COMMON_DIR)%.c $(COMMON_HEADERS)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -c $<

%.h: ;

clean:
	rm -f $(BINARY) $(ALL_OBJS) BW_TEST_FILE
