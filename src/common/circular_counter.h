#ifndef CIRCULAR_COUNTER_H
#define CIRCULAR_COUNTER_H

#include <sys/time.h>

struct circular_counter {
    int window_size;
    long bin_size;

    long *counts;

    struct timeval start_time;
    long current_bin_offset;
};

int ccount_init(struct circular_counter *cc, int window_size, long bin_size);
void ccount_destroy(struct circular_counter *cc);
int ccount_rotate(struct circular_counter *cc);
long ccount_read(struct circular_counter *cc);
void ccount_set(struct circular_counter *cc, long value);
long ccount_inc(struct circular_counter *cc, long amount);
long ccount_sum(struct circular_counter *cc);

#endif /* CIRCULAR_COUNTER_H */
