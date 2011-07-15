#include <sys/time.h>

#include "timing.h"

long timeval_diff(const struct timeval *lhs, const struct timeval *rhs)
{
    return (long)(lhs->tv_sec - rhs->tv_sec) * (long)USEC_PER_SEC +
            (long)(lhs->tv_usec - rhs->tv_usec);
}

void set_timeval_usec(long usec, struct timeval *dest)
{
    dest->tv_sec = usec / USEC_PER_SEC;
    dest->tv_usec = usec % USEC_PER_SEC;
}

