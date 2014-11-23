#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "packet.h"

struct packet *alloc_packet(int head_size, int tail_size)
{
    struct packet *pkt = malloc(sizeof(struct packet));
    if (!pkt)
        return NULL;

    pkt->buffer_size = head_size + tail_size;

    pkt->buffer = malloc(pkt->buffer_size);
    if (!pkt->buffer) {
        free(pkt);
        return NULL;
    }

    pkt->data = pkt->buffer + head_size;
    pkt->head_size = head_size;
    pkt->data_size = 0;
    pkt->tail_size = tail_size;
    pkt->next = NULL;
    
    return pkt;
}

struct packet *clone_packet(struct packet *pkt)
{
    struct packet *newpkt = malloc(sizeof(struct packet));
    if (!newpkt)
        return NULL;

    newpkt->buffer_size = pkt->buffer_size;

    newpkt->buffer = malloc(newpkt->buffer_size);
    if (!newpkt->buffer) {
        free(newpkt);
        return NULL;
    }

    newpkt->data = newpkt->buffer + pkt->head_size;
    newpkt->head_size = pkt->head_size;
    newpkt->data_size = pkt->data_size;
    newpkt->tail_size = pkt->tail_size;
    newpkt->next = NULL;

    memcpy(newpkt->data, pkt->data, newpkt->data_size);

    return newpkt;
}

void free_packet(struct packet *pkt)
{
    if (pkt->buffer) {
        free(pkt->buffer);
        pkt->buffer = NULL;
    }
    free(pkt);
}

void packet_put(struct packet *pkt, int bytes)
{
    assert(pkt->tail_size >= bytes);
    pkt->data_size += bytes;
    pkt->tail_size -= bytes;
}

void packet_pull(struct packet *pkt, int bytes)
{
    assert(pkt->data_size >= bytes);
    pkt->data += bytes;
    pkt->head_size += bytes;
    pkt->data_size -= bytes;
}

