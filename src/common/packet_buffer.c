#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "debug.h"
#include "packet.h"
#include "packet_buffer.h"
#include "rwlock.h"

#define INTEGER_WRAP_AROUND 0x7FFFFFFF

int pb_seq_is_larger(uint32_t seq, uint32_t next_seq)
{
    return next_seq >= seq || (seq > INTEGER_WRAP_AROUND && next_seq < seq - INTEGER_WRAP_AROUND);
}

int pb_free_head(struct retrans_buffer *rt_buffer)
{
    if(rt_buffer->head == NULL) { return FAILURE; }
    struct retrans_buffer_entry *to_remove = rt_buffer->head;
    rt_buffer->head = to_remove->next;
    free_packet(to_remove->pkt);
    free(to_remove);
    rt_buffer->length--;
    return SUCCESS;
}

int pb_add_packet(struct retrans_buffer *rt_buffer, uint32_t seq, struct packet *pkt)
{
    if(seq == 0 || pkt->data_size == 0){ 
        free_packet(pkt);
        return rt_buffer->length;
    }
    
    if(rt_buffer->length > 0 && !pb_seq_is_larger(rt_buffer->tail->seq, seq)){
        DEBUG_MSG("Prev sequence number %d is greater than new sequence number %d",rt_buffer->tail->seq, seq);
        return rt_buffer->length;
    }

    if(rt_buffer->length >= RETRANSMIT_BUFFER_SIZE)
    {
        pb_free_head(rt_buffer);
    }

    struct retrans_buffer_entry *to_add = (struct retrans_buffer_entry *)malloc(sizeof(struct retrans_buffer_entry));

    to_add->seq = seq;
    to_add->pkt = pkt;
    to_add->next = NULL;
    if(rt_buffer->length == 0) {
        rt_buffer->head = to_add;
        rt_buffer->tail = to_add;
    }
    else{
        rt_buffer->tail->next = to_add;
        rt_buffer->tail = to_add;
    }
    rt_buffer->length++;
    return rt_buffer->length;
}
int pb_free_packets(struct retrans_buffer *rt_buffer, uint32_t seq)
{
    while(rt_buffer->head != NULL && pb_seq_is_larger(rt_buffer->head->seq, seq))
    {
        pb_free_head(rt_buffer);
    }
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
    if(prev_seq == 0 || (seq != prev_seq && seq - prev_seq < INTEGER_WRAP_AROUND)) {
        packet_buffer[index] = seq;
        return NOT_DUPLICATE;
    }
    return DUPLICATE;
}

void pb_clear_buffer(uint32_t *received_buffer) {
    memset(received_buffer, 0, sizeof(uint32_t) * PACKET_BUFFER_SIZE);
}
