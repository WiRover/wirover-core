#ifndef RATE_CONTROL_H
#define RATE_CONTROL_H

#include <sys/time.h>

#include "circular_buffer.h"

struct rate_control {
    double capacity;
    struct circular_buffer cbuffer;

};

int rc_init(struct rate_control *cc, int window_size, long bin_size, double capacity);
long update_tx_rate(struct rate_control *cc, long amount);
float rc_sum(struct rate_control *cc);

// Rate information
int has_capacity(struct rate_control *cc);
double current_allocation(struct rate_control *cc);

#endif /* RATE_CONTROL_H */
