#ifndef RATE_CONTROL_H
#define RATE_CONTROL_H

#include <sys/time.h>

struct rate_control {
    double capacity;
    int window_size;
    long bin_size;

    float *counts;

    struct timeval start_time;
    long current_bin_offset;
};

int rc_init(struct rate_control *cc, int window_size, long bin_size, double capacity);
void rc_destroy(struct rate_control *cc);
int rc_rotate(struct rate_control *cc);
long rc_read(struct rate_control *cc);
void rc_set(struct rate_control *cc, long value);
long update_tx_rate(struct rate_control *cc, long amount);
float rc_sum(struct rate_control *cc);

// Rate information
int has_capacity(struct rate_control *cc);
double current_allocation(struct rate_control *cc);

#endif /* RATE_CONTROL_H */
