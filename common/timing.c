#include <assert.h>
#include <errno.h>
#include <sys/time.h>

#include "debug.h"
#include "timing.h"

void timeval_sub(struct timeval *result, const struct timeval *lhs, 
                const struct timeval *rhs)
{
    assert(result && lhs && rhs);

    result->tv_sec  = lhs->tv_sec - rhs->tv_sec;
    result->tv_usec = lhs->tv_usec - rhs->tv_usec;

    if(result->tv_usec >= USEC_PER_SEC) {
        int xsec = (result->tv_usec / USEC_PER_SEC);
        result->tv_sec  += xsec;
        result->tv_usec -= xsec * USEC_PER_SEC;
    } else if(result->tv_usec < 0) {
        int xsec = (-result->tv_usec / USEC_PER_SEC) + 1;
        result->tv_sec  -= xsec;
        result->tv_usec += xsec * USEC_PER_SEC;
    }
}

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

