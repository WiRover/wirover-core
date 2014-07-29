#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "debug.h"
#include "packet_buffer.h"

int pb_free_head(struct retrans_buffer *rt_buffer)
{
    if(rt_buffer->head == NULL) { return FAILURE; }
    struct retrans_buffer_entry *to_remove = rt_buffer->head;
    rt_buffer->head = to_remove->next;
    free(to_remove->packet);
    free(to_remove);
    rt_buffer->length--;
    return SUCCESS;
}

int pb_add_packet(struct retrans_buffer *rt_buffer, uint32_t seq, char* packet, int size)
{
    if(seq == 0 || size == 0){ return rt_buffer->length; }
    if(rt_buffer->length >= RETRANSMIT_BUFFER_SIZE)
    {
        pb_free_head(rt_buffer);
    }
    struct retrans_buffer_entry *to_add = (struct retrans_buffer_entry *)malloc(sizeof(struct retrans_buffer_entry));

    to_add->seq = seq;
    to_add->packet = (char *)malloc(size);
    memcpy(to_add->packet, packet, size);
    to_add->size = size;
    to_add->next = NULL;
    if(rt_buffer->length == 0) {
        rt_buffer->head = to_add;
        rt_buffer->tail = to_add;
    }
    else{
        if(rt_buffer->tail->seq >= to_add->seq){
        DEBUG_MSG("Prev sequence number %d, new sequence number %d",rt_buffer->tail->seq, to_add->seq);
        }
        rt_buffer->tail->next = to_add;
        rt_buffer->tail = to_add;
    }
    rt_buffer->length++;
    return rt_buffer->length;
}
int pb_free_packets(struct retrans_buffer *rt_buffer, uint32_t seq)
{
    while(rt_buffer->head != NULL && rt_buffer->head->seq <= seq)
    {
        pb_free_head(rt_buffer);
    }
    /*if(rt_buffer->head == NULL) { DEBUG_MSG("Emptied buffer has length %d", rt_buffer->length); }
    else
        DEBUG_MSG("Buffer head has seq %d and removed up to %d", rt_buffer->head->seq, seq);*/
    return rt_buffer->length;
}

uint32_t *pb_alloc_seq_buffer() { 
    uint32_t *output = (uint32_t *)malloc(sizeof(uint32_t) * PACKET_BUFFER_SIZE);
    memset(output, 0, sizeof(uint32_t) * PACKET_BUFFER_SIZE);
    return output;
}

int pb_add_seq_num(uint32_t *packet_buffer, uint32_t seq) {
    //Packets with seq_num = 0 are a special case that we will just ignore and pass regardless
    //but not put them in our buffer
    if(seq == 0){ return NOT_DUPLICATE; }

    int index = seq % PACKET_BUFFER_SIZE;
    
    uint32_t prev_seq = packet_buffer[index];
    //The last case is if the sequence number overflows
    if(seq > prev_seq || (seq <= prev_seq && seq > prev_seq - WRAP_AROUND_BOUND)) {
        packet_buffer[index] = seq;
        return NOT_DUPLICATE;
    }
    DEBUG_MSG("Dropping duplicate packet");
    return DUPLICATE;
}

