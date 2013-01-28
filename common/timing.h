#ifndef TIMING_H
#define TIMING_H

#ifndef USEC_PER_SEC
#define USEC_PER_SEC 1000000
#endif

struct timeval;

long timeval_diff(const struct timeval *lhs, const struct timeval *rhs);
void timeval_add_us(struct timeval *dest, long usec);
void set_timeval_us(struct timeval *dest, long usec);
void set_timeval_usec(long usec, struct timeval *dest);
int safe_usleep(long usec);

long get_elapsed_us(struct timeval *start);

#endif /* TIMING_H */

