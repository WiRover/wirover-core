#ifndef CIRCULAR_COUNTER_H
#define CIRCULAR_COUNTER_H

struct circular_counter {
    int size;
    int window_size;
    long bin_size;

    int bitmask;

    long start_time;
    int start_index;
    long *counts;
};

int ccount_init(struct circular_counter *cc, int window_size, long bin_size);
void ccount_destroy(struct circular_counter *cc);
int ccount_rotate(struct circular_counter *cc, long t);
long ccount_read(struct circular_counter *cc, long t);
void ccount_set(struct circular_counter *cc, long t, long value);
long ccount_inc(struct circular_counter *cc, long t, long amount);
long ccount_sum(struct circular_counter *cc, long t);

#endif /* CIRCULAR_COUNTER_H */
