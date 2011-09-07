#ifndef TIMING_H
#define TIMING_H

#ifndef USEC_PER_SEC
#define USEC_PER_SEC 1000000
#endif

struct timeval;

void timeval_sub(struct timeval *result, const struct timeval *lhs, 
        const struct timeval *rhs);
long timeval_diff(const struct timeval *lhs, const struct timeval *rhs);
void set_timeval_usec(long usec, struct timeval *dest);

#endif /* TIMING_H */

