/*
 * packetBuffer.h
 */

#include "rwlock.h"

#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H

#define RETRANSMIT_BUFFER_SIZE 128

#define PACKET_BUFFER_SIZE 128

#define DUPLICATE 0
#define NOT_DUPLICATE 1

struct retrans_buffer_entry {
    uint32_t                         seq;
    struct packet *                  pkt;
    struct retrans_buffer_entry*     next;
};

struct retrans_buffer {
    unsigned int                    length;
    struct retrans_buffer_entry*    head;
    struct retrans_buffer_entry*    tail;
    struct rwlock                   rwlock;
};

int pb_add_packet(struct retrans_buffer *rt_buffer, uint32_t seq, struct packet *pkt);
int pb_free_packets(struct retrans_buffer *rt_buffer, uint32_t seq);
int pb_free_head(struct retrans_buffer *rt_buffer);

uint32_t *pb_alloc_seq_buffer();
int pb_add_seq_num(uint32_t *received_buffer, uint32_t seq);
void pb_clear_buffer(uint32_t *received_buffer);



#endif //PACKET_BUFFER_H
