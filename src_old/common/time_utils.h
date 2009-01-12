#ifndef _TIME_UTILS_H_
#define _TIME_UTILS_H_

#define USEC_PER_SEC        1000000

void set_timeval_us(struct timeval* tv, int us);

void timeval_sum(struct timeval* result, const struct timeval* start, const struct timeval* end);
void timeval_diff(struct timeval* result, const struct timeval* start, const struct timeval* end);

void safe_sleep(unsigned int seconds);

#endif //_TIME_UTILS_H_

