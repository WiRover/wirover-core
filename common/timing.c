#include <assert.h>
#include <errno.h>
#include <sys/time.h>

#include "debug.h"
#include "timing.h"

long timeval_diff(const struct timeval *lhs, const struct timeval *rhs)
{
    return (long)(lhs->tv_sec - rhs->tv_sec) * (long)USEC_PER_SEC +
            (long)(lhs->tv_usec - rhs->tv_usec);
}

void timeval_add_us(struct timeval *dest, long usec)
{
    dest->tv_sec += usec / USEC_PER_SEC;
    dest->tv_usec += usec % USEC_PER_SEC;

    dest->tv_sec += dest->tv_usec / USEC_PER_SEC;
    dest->tv_usec = dest->tv_usec % USEC_PER_SEC;
}

void set_timeval_usec(long usec, struct timeval *dest)
{
    dest->tv_sec = usec / USEC_PER_SEC;
    dest->tv_usec = usec % USEC_PER_SEC;
}

void set_timeval_us(struct timeval *dest, long usec)
{
    dest->tv_sec = usec / USEC_PER_SEC;
    dest->tv_usec = usec % USEC_PER_SEC;
}

int safe_usleep(long usec)
{
    struct timeval sleep;
    sleep.tv_sec = usec / USEC_PER_SEC;
    sleep.tv_usec = usec % USEC_PER_SEC;

    int rtn = select(0, 0, 0, 0, &sleep);
    if(rtn < 0 && errno == EINTR) {
        DEBUG_MSG("Warning: select() was interrupted");
    }

    return rtn;
}

long get_elapsed_us(struct timeval *start)
{
    struct timeval stop;
    gettimeofday(&stop, 0);

    return (long)(stop.tv_sec - start->tv_sec) * (long)USEC_PER_SEC +
            (long)(stop.tv_usec - start->tv_usec);
}

