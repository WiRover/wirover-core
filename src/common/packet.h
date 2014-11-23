#ifndef PACKET_H
#define PACKET_H

/* This is modeled after skbuff in Linux kernel. */

struct packet {
    char *buffer;

    /* Data for reading starts here and extends data_size bytes. */
    char *data;

    int buffer_size;
    int head_size;
    int data_size;
    int tail_size;

    /* Next packet in a queue. */
    struct packet *next;
};

struct packet *alloc_packet(int head_size, int tail_size);
struct packet *clone_packet(struct packet *pkt);
void free_packet(struct packet *pkt);

void packet_put(struct packet *pkt, int bytes);
void packet_pull(struct packet *pkt, int bytes);

#endif /* PACKET_H */
