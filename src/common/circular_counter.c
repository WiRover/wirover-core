#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "circular_counter.h"
#include "timing.h"
#include "debug.h"

/* 
 * window_size: minimum length of history to keep (as a number of bins)
 * bin_size: size of each bin in time units
 * capacity: the counter's capacity in Mbit/s
 */
int ccount_init(struct circular_counter *cc, int window_size, long bin_size, double capacity)
{
    assert(window_size > 0);
    assert(bin_size > 0);

    cc->capacity = capacity;
    cc->window_size = window_size;
    cc->bin_size = bin_size;

    cc->counts = calloc(cc->window_size, sizeof(*cc->counts));
    if(!cc->counts)
        return -1;

    gettimeofday(&cc->start_time, NULL);
    cc->current_bin_offset = 0;

    return 0;
}

/* Does not free the circular_counter structure itself. */
void ccount_destroy(struct circular_counter *cc)
{
    if(cc->counts) {
        free(cc->counts);
        cc->counts = NULL;
    }
}

/* 
 * Update the data structure for the current time and return the index
 * into the counts array for the bin associated with the current time.
 *
 * This function is intended for internal use by the ccount_{read,set,inc} functions.
 */
int ccount_rotate(struct circular_counter *cc)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    long diff = timeval_diff(&now, &cc->start_time) / cc->bin_size;
    long bin_diff = diff - cc->current_bin_offset;
    if(bin_diff < 0) {
        DEBUG_MSG("CCount error, offset less than 0");
        return 0;
    }
    // A bin_diff greater than the window size means we can clear
    // the whole counter and set our offset to the diff
    if(bin_diff >= cc->window_size) {
        cc->current_bin_offset = diff;
        memset(cc->counts, 0, sizeof(*cc->counts) * cc->window_size);
    }

    // Each time we have to move forward in our circular buffer
    // we clear the next bin and move our offset to point to it
    int new_index = (diff) % cc->window_size;
    while(cc->current_bin_offset % cc->window_size != new_index) {
        cc->current_bin_offset ++;
        cc->counts[cc->current_bin_offset % cc->window_size] = 0;
    }
    return new_index;
}

/* Read the counter for the bin at time t. */
long ccount_read(struct circular_counter *cc)
{
    int i = ccount_rotate(cc);
    return cc->counts[i];
}

/* Set the counter for the bin at time t. */
void ccount_set(struct circular_counter *cc, long value)
{
    int i = ccount_rotate(cc);
    cc->counts[i] = value;
}

/* Starting from t, sum the past window of data. */
long ccount_sum(struct circular_counter *cc)
{
    long sum = 0;
    ccount_rotate(cc);
    for(int j = 0; j < cc->window_size; j++) {
        sum += cc->counts[j];
    }
    return sum;
}

/* Test if the target has remaining capacity to send another packet.  Returns
 * true/false.  This could be augmented to consider the size of the packet to
 * be sent. */
int has_capacity(struct circular_counter *cc)
{
    double count = current_allocation(cc);
    return (count < cc->capacity);
}

/* Return the counter's current allocation in Mbit/s */
double current_allocation(struct circular_counter *cc)
{
    long count = ccount_sum(cc);
    return count * 8.0 / (cc->window_size * cc->bin_size);
}

/* Increment the counter for the bin at time t and return the result. */
long update_tx_rate(struct circular_counter *cc, long amount)
{
    int i = ccount_rotate(cc);
    cc->counts[i] += amount;
    return cc->counts[i];
}