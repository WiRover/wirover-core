/*
 * debug.c: most message printing facilities are moved to debug.h
 *
 */
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include "debug.h"

/* For backtrace logging */
#include <syslog.h>
#include <execinfo.h>

#if defined(DEBUG_PRINT) || defined(ERROR_PRINT) || defined(STATS_PRINT)
/* Print time information to the buffer. */
int snprintf_time(char* buffer, size_t len)
{
    struct timeval now;
    struct tm broken;

    gettimeofday(&now, 0);
    localtime_r(&now.tv_sec, &broken);

    return snprintf(buffer, len, "%02d/%02d/%04d %02d:%02d:%02d.%06d",
            broken.tm_mon + 1, broken.tm_mday, broken.tm_year + 1900,
            broken.tm_hour, broken.tm_min, broken.tm_sec, (int)now.tv_usec);
}
#endif

#if defined(DEBUG_PRINT) || defined(ERROR_PRINT)
/*
 * Print file name to the buffer.
 * Ignore the leading '/' if it is a full path.
 */
int snprintf_file(char* buffer, size_t len, char *file)
{
    return snprintf(buffer, len, "%s",
            strrchr(file, '/') == NULL ? file : file++);
}
#endif

/* Send backtrace to system log, using library call directly. */
void log_backtrace()
{
    void* ptrs[MAX_BACKTRACE_LEN];
    int i, nptrs = backtrace(ptrs, MAX_BACKTRACE_LEN);

    char** symbols;
    symbols = backtrace_symbols(ptrs, nptrs);
    if(!symbols) {
        perror("backtrace_symbols");
        return;
    }

    openlog("WiRover [backtrace] ", LOG_CONS | LOG_NDELAY, LOG_SYSLOG);
    for(i = 0; i < nptrs; i++)
        syslog(LOG_ERR, "(%2d) %s\n", i, symbols[i]);
    closelog();

    free(symbols);
}
