#ifndef CIRCULAR_COUNTER_H
#define CIRCULAR_COUNTER_H

#include <sys/time.h>

struct circular_counter {
    double capacity;
    int window_size;
    long bin_size;

    long *counts;

    struct timeval start_time;
    long current_bin_offset;
};

int ccount_init(struct circular_counter *cc, int window_size, long bin_size, double capacity);
void ccount_destroy(struct circular_counter *cc);
int ccount_rotate(struct circular_counter *cc);
long ccount_read(struct circular_counter *cc);
void ccount_set(struct circular_counter *cc, long value);
long update_tx_rate(struct circular_counter *cc, long amount);
long ccount_sum(struct circular_counter *cc);

// Rate information
int has_capacity(struct circular_counter *cc);
double current_allocation(struct circular_counter *cc);

#endif /* CIRCULAR_COUNTER_H */
