#include <assert.h>
#include <errno.h>
#include <sys/time.h>

#include "debug.h"
#include "time_utils.h"

/*
 * SET TIMEVAL US
 *
 * Fills a timeval structure with the time given in microseconds.
 */
inline void set_timeval_us(struct timeval* tv, int us)
{
	assert(tv);
	tv->tv_sec = us / USEC_PER_SEC;
	tv->tv_usec = us % USEC_PER_SEC;
}

void timeval_sum(struct timeval* result, const struct timeval* start, const struct timeval* end)
{
    assert(result && start && end);

    result->tv_sec  = end->tv_sec + start->tv_sec;
    result->tv_usec = end->tv_usec + start->tv_usec;

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

void timeval_diff(struct timeval* result, const struct timeval* start, const struct timeval* end)
{
    assert(result && start && end);

    result->tv_sec  = end->tv_sec - start->tv_sec;
    result->tv_usec = end->tv_usec - start->tv_usec;

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

void safe_sleep(unsigned int seconds)
{
    struct timeval sleep;
    sleep.tv_sec = seconds;
    sleep.tv_usec = 0;

    int rtn = select(0, 0, 0, 0, &sleep);
    if(rtn < 0 && errno == EINTR) {
        // If this happens a lot, you may need to do something to block the
        // signal that is interrupting this.  Switch to pselect or set the
        // sigmask of the calling thread.
        DEBUG_MSG("Warning: select() was interrupted");
    }
}


