#ifndef PACKET_H
#define PACKET_H

#include <sys/time.h>

/* This is modeled after skbuff in Linux kernel. */

struct packet {
    struct timeval created;

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
void packet_push(struct packet *pkt, int bytes);
void packet_pull(struct packet *pkt, int bytes);
void packet_pull_tail(struct packet *pkt, int bytes);

int packet_queue_append(struct packet **tx_queue_head, struct packet **tx_queue_tail, struct packet *pkt);
struct packet * packet_queue_dequeue(struct packet **tx_queue_head);

#endif /* PACKET_H */
