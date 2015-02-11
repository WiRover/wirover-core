#ifndef CIRCULAR_BUFFER_H
#define CIRCULAR_BUFFER_H

#include <sys/time.h>

struct circular_buffer
{
    int window_size;
    long bin_size;
    float *counts;
    struct timeval start_time;
    long current_bin_offset;
};
int cbuffer_init(struct circular_buffer *cb, int window_size, long bin_size);
void destroy_cbuffer(struct circular_buffer *cb);
int cbuffer_rotate(struct circular_buffer *cb);
float cbuffer_sum(struct circular_buffer *cb);
float cbuffer_min(struct circular_buffer *cb);
float *cbuffer_current(struct circular_buffer *cb);

#endif /* CIRCULAR_BUFFER_H */