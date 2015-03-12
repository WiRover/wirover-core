#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "constants.h"
#include "debug.h"
#include "timing.h"

long timeval_diff(const struct timeval *lhs, const struct timeval *rhs)
{
    return (long)(lhs->tv_sec - rhs->tv_sec) * (long)USECS_PER_SEC +
            (long)(lhs->tv_usec - rhs->tv_usec);
}

void timeval_add_us(struct timeval *dest, long usec)
{
    dest->tv_sec += usec / USECS_PER_SEC;
    dest->tv_usec += usec % USECS_PER_SEC;

    dest->tv_sec += dest->tv_usec / USECS_PER_SEC;
    dest->tv_usec = dest->tv_usec % USECS_PER_SEC;
}

void set_timeval_usec(long usec, struct timeval *dest)
{
    dest->tv_sec = usec / USECS_PER_SEC;
    dest->tv_usec = usec % USECS_PER_SEC;
}

void set_timeval_us(struct timeval *dest, long usec)
{
    dest->tv_sec = usec / USECS_PER_SEC;
    dest->tv_usec = usec % USECS_PER_SEC;
}

int safe_usleep(long usec)
{
    struct timeval sleep;
    sleep.tv_sec = usec / USECS_PER_SEC;
    sleep.tv_usec = usec % USECS_PER_SEC;

    int rtn = select(0, 0, 0, 0, &sleep);
    if(rtn < 0 && errno == EINTR) {
        DEBUG_MSG("Warning: select() was interrupted");
    }

    return rtn;
}

int64_t get_elapsed_us(struct timeval *start)
{
    struct timeval stop;
    get_monotonic_time(&stop);

    int64_t output = (int64_t)(stop.tv_sec - start->tv_sec) * (int64_t)USECS_PER_SEC +
            (int64_t)(stop.tv_usec - start->tv_usec);
    if(output < 0)
        DEBUG_MSG("Elapsed time < 0 %d %ld - %d %ld = %ld", stop.tv_sec, stop.tv_usec, start->tv_sec, start->tv_usec, output);
    return output;
}

int get_monotonic_time(struct timeval *dst)
{
    struct timespec ts;
    int rtn = clock_gettime(CLOCK_MONOTONIC, &ts);
    dst->tv_sec = ts.tv_sec;
    dst->tv_usec = ts.tv_nsec / NSECS_PER_USEC;

    return rtn;
}

/*
 * Exponential increase with bounds checking.
 *
 * Returns 2x the current value.  If the current value is less than the
 * minimum, then the current value is increased to the minimum before doubling.
 * If the result is greater than the maximum value, then the maximum value is
 * returned.
 */
int exp_inc(int curr, int min, int max)
{
    if(curr < min)
        curr = min;

    curr *= 2;
    if(curr > max)
        curr = max;

    return curr;
}

/*
 * Sleep for an exponentially increasing period of time.
 *
 * This function sleep for the given delay, then return the next (doubled)
 * sleep period.  If the given delay is less than the minimum, it is increased
 * to the minimum first.  The returned value will always be at most the
 * maximum.
 */
int exp_delay(int delay, int min, int max)
{
    if(delay < min)
        delay = min;

    sleep(delay);

    delay *= 2;
    if(delay > max)
        delay = max;

    return delay;
}


