/*
 * packetBuffer.h
 */

#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H

#define RETRANSMIT_BUFFER_SIZE 128

#define PACKET_BUFFER_SIZE 128
#define WRAP_AROUND_BOUND 0xEFFFFFFF

#define DUPLICATE 0
#define NOT_DUPLICATE 1

struct retrans_buffer_entry {
    uint32_t                         seq;
    char*                            packet;
    int                              size;
    struct retrans_buffer_entry*     next;
};

struct retrans_buffer {
    unsigned int                    length;
    struct retrans_buffer_entry*    head;
    struct retrans_buffer_entry*    tail;
};

int pb_add_packet(struct retrans_buffer *rt_buffer, uint32_t seq, char* packet, int size);
int pb_free_packets(struct retrans_buffer *rt_buffer, uint32_t seq);
int pb_free_head(struct retrans_buffer *rt_buffer);

uint32_t *pb_alloc_seq_buffer();
int pb_add_seq_num(uint32_t *received_buffer, uint32_t seq);



#endif //PACKET_BUFFER_H
