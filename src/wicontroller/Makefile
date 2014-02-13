CC=gcc
CFLAGS=-g -D CONTROLLER -std=gnu99 -pedantic -fstrict-aliasing -I/usr/include/mysql -rdynamic -L/usr/lib/mysql
OBJECTS= main.o contChan.o selectInterface.o tunnelInterface.o packet_debug.o reOrderPackets.o utils.o special.o algoPerConnWrr.o gatewayUpdater.o udp_ping.o active_bw.o sockets.o link.o time_utils.o passive_bw.o debug.o
BINARY= wicontroller 

all:$(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -g -o $(BINARY) -lpthread -lm -lmysqlclient

main.o: main.c 
	$(CC) $(CFLAGS) -c main.c

utils.o: ../common/utils.c ../common/utils.h ../common/parameters.h
	$(CC) $(CFLAGS) -c ../common/utils.c 

selectInterface.o: selectInterface.c selectInterface.h ../common/parameters.h
	$(CC) $(CFLAGS) -c selectInterface.c

algoPerConnWrr.o: algoPerConnWrr.c ../common/interface.h
	$(CC) $(CFLAGS) -c algoPerConnWrr.c

special.o: ../common/special.c ../common/special.h ../common/parameters.h
	$(CC) $(CFLAGS) -c ../common/special.c

tunnelInterface.o: ../common/tunnelInterface.c ../common/tunnelInterface.h ../common/parameters.h
	$(CC) $(CFLAGS) -c ../common/tunnelInterface.c

packet_debug.o: ../common/packet_debug.c ../common/packet_debug.h ../common/parameters.h 
	$(CC) $(CFLAGS) -c ../common/packet_debug.c

reOrderPackets.o: ../common/reOrderPackets.c ../common/reOrderPackets.h ../common/parameters.h
	$(CC) $(CFLAGS) -c ../common/reOrderPackets.c 

contChan.o: contChan.c ../common/contChan.h ../common/parameters.h
	$(CC) $(CFLAGS) -c contChan.c

gatewayUpdater.o: gatewayUpdater.c gatewayUpdater.h
	$(CC) $(CFLAGS) -c gatewayUpdater.c

udp_ping.o: udp_ping.c ../common/udp_ping.h
	$(CC) $(CFLAGS) -c udp_ping.c

active_bw.o: active_bw.c ../common/active_bw.h
	$(CC) $(CFLAGS) -c active_bw.c

sockets.o: ../common/sockets.c ../common/sockets.h
	$(CC) $(CFLAGS) -c ../common/sockets.c

link.o: ../common/link.c ../common/link.h
	$(CC) $(CFLAGS) -c ../common/link.c

time_utils.o: ../common/time_utils.c ../common/time_utils.h
	$(CC) $(CFLAGS) -c ../common/time_utils.c

passive_bw.o: ../common/passive_bw.c ../common/passive_bw.h
	$(CC) $(CFLAGS) -c ../common/passive_bw.c

debug.o: ../common/debug.c ../common/debug.h
	$(CC) $(CFLAGS) -c ../common/debug.c

clean: 
	rm -f $(BINARY) $(OBJECTS) ../common/*.o 

install:
	../../scripts/wicontroller/install
	
