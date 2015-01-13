#include <assert.h>
#include <stdlib.h>
#include <string.h>

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
    assert(window_size > 0);
    assert(bin_size > 0);

    rc->capacity = capacity;
    rc->window_size = window_size;
    rc->bin_size = bin_size;

    rc->counts = calloc(rc->window_size, sizeof(*rc->counts));
    if(!rc->counts)
        return -1;

    gettimeofday(&rc->start_time, NULL);
    rc->current_bin_offset = 0;

    return 0;
}

/* Does not free the rate_control structure itself. */
void rc_destroy(struct rate_control *rc)
{
    if(rc->counts) {
        free(rc->counts);
        rc->counts = NULL;
    }
}

/* 
 * Update the data structure for the current time and return the index
 * into the counts array for the bin associated with the current time.
 *
 * This function is intended for internal use by the rc_{read,set,inc} functions.
 */
int rc_rotate(struct rate_control *rc)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    long diff = timeval_diff(&now, &rc->start_time) / rc->bin_size;
    long bin_diff = diff - rc->current_bin_offset;
    if(bin_diff < 0) {
        DEBUG_MSG("rc error, offset less than 0");
        return 0;
    }

    // A bin_diff greater than the window size means we can clear
    // the whole counter and set our offset to the diff
    if(bin_diff >= rc->window_size) {
        rc->current_bin_offset = diff;
        memset(rc->counts, 0, sizeof(*rc->counts) * rc->window_size);
    }

    // Each time we have to move forward in our circular buffer
    // we clear the next bin and move our offset to point to it
    int new_index = (diff) % rc->window_size;
    while(rc->current_bin_offset % rc->window_size != new_index) {
        rc->current_bin_offset ++;
        rc->counts[rc->current_bin_offset % rc->window_size] = 0;
    }
    return new_index;
}

/* Read the counter for the bin at time t. */
long rc_read(struct rate_control *rc)
{
    int i = rc_rotate(rc);
    return rc->counts[i];
}

/* Set the counter for the bin at time t. */
void rc_set(struct rate_control *rc, long value)
{
    int i = rc_rotate(rc);
    rc->counts[i] = value;
}

/* Starting from t, sum the past window of data. */
float rc_sum(struct rate_control *rc)
{
    float sum = 0;
    rc_rotate(rc);
    for(int j = 0; j < rc->window_size; j++) {
        sum += rc->counts[j];
    }
    return sum;
}

/* Test if the target has remaining capacity to send another packet.  Returns
 * true/false.  This could be augmented to consider the size of the packet to
 * be sent. */
int has_capacity(struct rate_control *rc)
{
    float count = rc_sum(rc);
    return (count < rc->capacity * rc->bin_size * (rc->window_size + 1) / 16);
}

/* Return the counter's current allocation in Mbit/s */
double current_allocation(struct rate_control *rc)
{
    float count = rc_sum(rc);
    return count * 8.0 / (rc->window_size * rc->bin_size);
}

/* Increment the counter for the bin at time t and return the result. */
long update_tx_rate(struct rate_control *rc, long amount)
{
    for(int i = 0; i < rc->window_size; i++)
    {
        rc->counts[i] += amount * 1.0f / rc->window_size;
    }
    return amount;
}