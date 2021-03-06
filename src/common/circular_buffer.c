#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "circular_buffer.h"
#include "debug.h"
#include "timing.h"

int cbuffer_init(struct circular_buffer *cb, int window_size, uint32_t bin_size)
{
    assert(window_size > 0);
    assert(bin_size > 0);

    if(!cb)
        return FAILURE;

    cb->window_size = window_size;
    cb->bin_size = bin_size;

    cb->counts = calloc(cb->window_size, sizeof(*cb->counts));
    if(!cb->counts)
        return FAILURE;

    get_monotonic_time(&cb->start_time);
    cb->current_bin_offset = 0;

    return SUCCESS;
}

void destroy_cbuffer(struct circular_buffer *cb)
{
    free(cb->counts);
}

/* 
 * Update the data structure for the current time and return the index
 * into the counts array for the bin associated with the current time.
 *
 * This function is intended for internal use.
 */
int cbuffer_rotate(struct circular_buffer *cb)
{
    int64_t diff = get_elapsed_us(&cb->start_time) / cb->bin_size;
    int64_t bin_diff = diff - cb->current_bin_offset;
    if(bin_diff < 0) {
        DEBUG_MSG("cb error, offset less than 0");
        destroy_cbuffer(cb);
        cbuffer_init(cb, cb->window_size, cb->bin_size);
        return 0;
    }

    // A bin_diff greater than the window size means we can clear
    // the whole counter and set our offset to the diff
    if(bin_diff >= cb->window_size) {
        cb->current_bin_offset = diff;
        memset(cb->counts, 0, sizeof(*cb->counts) * cb->window_size);
    }

    // Each time we have to move forward in our cicbular buffer
    // we clear the next bin and move our offset to point to it
    int new_index = (diff) % cb->window_size;
    while(cb->current_bin_offset % cb->window_size != new_index) {
        cb->current_bin_offset ++;
        cb->counts[cb->current_bin_offset % cb->window_size] = 0;
    }
    return new_index;
}

/* Starting from t, sum the past window of data. */
uint32_t cbuffer_sum(struct circular_buffer *cb)
{
    uint32_t sum = 0;
    cbuffer_rotate(cb);
    for(int j = 0; j < cb->window_size; j++) {
        sum += cb->counts[j];
    }
    return sum;
}

uint32_t cbuffer_min(struct circular_buffer *cb)
{
    uint32_t min = 0;
    cbuffer_rotate(cb);
    for(int j = 0; j < cb->window_size; j++) {
        uint32_t value = cb->counts[j];
        if(min == 0 || (value < min && value != 0))
        {
            min = value;
        }
    }
    return min;
}

uint32_t *cbuffer_current(struct circular_buffer *cb)
{
    return &cb->counts[cbuffer_rotate(cb)];
}