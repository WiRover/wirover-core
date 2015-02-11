#include <stdlib.h>
#include <string.h>

#include "packet.h"
#include "rate_control.h"
#include "timing.h"
#include "debug.h"

/* 
 * window_size: minimum length of history to keep (as a number of bins)
 * bin_size: size of each bin in time units
 * capacity: the counter's capacity in Mbit/s
 */
int rc_init(struct rate_control *rc, int window_size, long bin_size, double capacity)
{
    rc->capacity = capacity;

    if(cbuffer_init(&rc->cbuffer, window_size, bin_size) != SUCCESS)
        return -1;

    return 0;
}
void rc_destroy(struct rate_control *rc)
{
    while(rc->packet_queue_head) {
        struct packet * pkt = rc->packet_queue_head;
        packet_queue_dequeue(&rc->packet_queue_head);
        free_packet(pkt);
    }
    destroy_cbuffer(&rc->cbuffer);
}
void free_rc(struct rate_control *rc)
{
    rc_destroy(rc);
    free(rc);
}

/* Test if the target has remaining capacity to send another packet.  Returns
 * true/false.  This could be augmented to consider the size of the packet to
 * be sent. */
int has_capacity(struct rate_control *rc)
{
    float count = cbuffer_sum(&rc->cbuffer);
    return (count < rc->capacity * rc->cbuffer.bin_size * (rc->cbuffer.window_size + 1) / 16);
}

/* Return the counter's current allocation in Mbit/s */
double current_allocation(struct rate_control *rc)
{
    float count = cbuffer_sum(&rc->cbuffer);
    return count * 8.0 / (rc->cbuffer.window_size * rc->cbuffer.bin_size);
}

/* Increment the counter for the bin at time t and return the result. */
long update_tx_rate(struct rate_control *rc, long amount)
{
    for(int i = 0; i < rc->cbuffer.window_size; i++)
    {
        rc->cbuffer.counts[i] += amount * 1.0f / rc->cbuffer.window_size;
    }
    return amount;
}