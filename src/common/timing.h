#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>

struct timeval;

long timeval_diff(const struct timeval *lhs, const struct timeval *rhs);
void timeval_add_us(struct timeval *dest, long usec);
void set_timeval_us(struct timeval *dest, long usec);
void set_timeval_usec(long usec, struct timeval *dest);
int safe_usleep(long usec);

int64_t get_elapsed_us(struct timeval *start);
int get_monotonic_time(struct timeval *dst);

int exp_inc(int curr, int min, int max);
int exp_delay(int delay, int min, int max);

#endif /* TIMING_H */

