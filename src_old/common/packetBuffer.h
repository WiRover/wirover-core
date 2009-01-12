/*
 * packetBuffer.h
 */

#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H

#define PACKET_BUFFER_SIZE 128
#define WRAP_AROUND_BOUND 0xEFFFFFFF

#define ADDED 0
#define NOT_ADDED 1

struct buffer_storage {
    int seq_no;
};

int initPacketBuffer(struct buffer_storage *packet_buffer[]);
int addSeqNum(struct buffer_storage *packet_buffer[], int num);



#endif //PACKET_BUFFER_H
