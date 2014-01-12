#
# Makefile for WiRover gateway
#
# Compiling with -rdynamic adds some extra symbols that the program can print
# out during a stack trace in response to a segfault.

CC=gcc
BINARY=wigateway

#
# Allow command arguments to override default setting.
override CFLAGS += -Wall -D GATEWAY -dH -g -rdynamic -std=gnu99
override CFLAGS_STRICT += $(CFLAGS) -pedantic -fstrict-aliasing
override LINK_FLAGS +=-lssl -lpthread -lm -lrt -lpcap -lcrypto

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
	algoPerConnWrr.o \
	contChan.o \
	gpsHandler.o \
	interface.o \
	netlink.o \
	pcapSniff.o \
	scan.o \
	selectInterface.o
	#transfer.o

GATEWAY_STRICT_OBJS := active_bw.o udp_ping.o

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
	handleTransfer.o \
	myssl.o \
	packet_debug.o \
	reOrderPackets.o \
	special.o \
	tunnelInterface.o \
	utils.o
	# evdo_buffer.o \

COMMON_STRICT_OBJS := \
	debug.o \
	link.o \
	link_priority.o \
	passive_bw.o \
	sockets.o \
	time_utils.o

#
# Setup directory path and all object names.
COMMON_DIR := ../common/
COMMON_HEADERS := $(addprefix $(COMMON_DIR), $(COMMON_HEADER))
ALL_OBJS := $(COMMON_OBJS) $(COMMON_STRICT_OBJS) \
			$(GATEWAY_OBJS) $(GATEWAY_STRICT_OBJS)

#
# Rules for final executable
.PHONY: all
all: $(ALL_OBJS)
	$(CC) -g -rdynamic -o $(BINARY) $(LINK_FLAGS) $(ALL_OBJS)

#
# Rules for all objects, using static pattern rules (4.12).
# Output in current directory; do not pollute the common.
$(GATEWAY_OBJS): %.o: %.c $(GATEWAY_HEADERS) $(COMMON_HEADERS)
	$(CC) $(CFLAGS) -c $(subst .o,.c,$@)

$(GATEWAY_STRICT_OBJS): %.o: %.c $(GATEWAY_HEADERS) $(COMMON_HEADERS)
	$(CC) $(CFLAGS_STRICT) -c $(subst .o,.c,$@)

$(COMMON_OBJS): %.o: $(COMMON_DIR)%.c $(COMMON_HEADERS)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -c $<

$(COMMON_STRICT_OBJS): %.o: $(COMMON_DIR)%.c $(COMMON_HEADERS)
	$(CC) $(CFLAGS_STRICT) -I$(COMMON_DIR) -c $<

%.h: ;

clean:
	rm -f $(BINARY) $(ALL_OBJS) BW_TEST_FILE
