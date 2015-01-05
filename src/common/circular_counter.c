#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "circular_counter.h"
#include "timing.h"
#include "debug.h"

static inline int ilog2(unsigned x)
{
    int result = -1;
    while(x) {
        x >>= 1;
        result++;
    }
    return result;
}

/* 
 * window_size: minimum length of history to keep (as a number of bins)
 * bin_size: size of each bin in time units
 */
int ccount_init(struct circular_counter *cc, int window_size, long bin_size)
{
    assert(window_size > 0);
    assert(bin_size > 0);

    /* Make the array size a power of two for easy accesses. */
    cc->size = 1 << (ilog2(window_size-1) + 1);
    cc->window_size = window_size;
    cc->bin_size = bin_size;

    cc->bitmask = cc->size - 1;

    cc->counts = calloc(cc->size, sizeof(*cc->counts));
    if(!cc->counts)
        return -1;

    cc->time_offset = 0;
    gettimeofday(&cc->start_time, NULL);
    cc->start_index = 0;

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
 * Update the data structure for the new time t (should always be monotonically
 * non-decreasing) and return the index into the counts array for the bin
 * associated with time t.
 *
 * If t is beyond the current range of the array, then some or all of the oldest
 * bins will be cleared to make room.
 *
 * This function is intended for internal use by the ccount_{read,set,inc} functions.
 */
int ccount_rotate(struct circular_counter *cc)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    long diff = timeval_diff(&now, &cc->start_time) - cc->time_offset;
    long offset = diff / cc->bin_size;

    if(offset >= 0 && offset < cc->size) {
        return (cc->start_index + offset) & cc->bitmask;
    } else if(offset >= cc->size && offset < 2 * cc->size) {
        long rotate = offset - cc->size + 1;
        for(int i = 0; i < rotate; i++) {
            cc->counts[cc->start_index] = 0;
            cc->start_index = (cc->start_index + 1) & cc->bitmask;
        }
        cc->time_offset += cc->bin_size * rotate;
        return (cc->start_index - 1) & cc->bitmask;
    } else {
        cc->start_time = now;
        cc->time_offset = 0;
        cc->start_index = 0;
        memset(cc->counts, 0, sizeof(*cc->counts) * cc->size);
        return 0;
    }
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

/* Increment the counter for the bin at time t and return the result. */
long ccount_inc(struct circular_counter *cc, long amount)
{
    int i = ccount_rotate(cc);
    cc->counts[i] += amount;
    return cc->counts[i];
}

/* Starting from t, sum the past window of data. */
long ccount_sum(struct circular_counter *cc)
{
    long sum = 0;
    int i = ccount_rotate(cc);
    for(int j = 0; j < cc->window_size; j++) {
        sum += cc->counts[i];
        i = (i - 1) & cc->bitmask;
    }
    return sum;
}
