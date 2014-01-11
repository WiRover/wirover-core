#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>
#include <assert.h>
#include <string.h> //for strerror
#include "utils.h"

#define MAX_DEBUG_LEN           1024
#define MAX_BACKTRACE_LEN       100

#ifndef FAILURE
#define FAILURE -1
#endif

#ifndef SUCCESS
#define SUCCESS 0
#endif

/* Print time and file name to the buffer */
int snprintf_time(char* buffer, size_t len);
int snprintf_file(char* buffer, size_t len, char *file);

/* Calculate space remained for all snprintf */
#define SIZE_REMAIN(_buf, _p) \
    ((_p) - (_buf) > sizeof(_buf) ? 0 : sizeof(_buf) - ((_p) - (_buf)))

/* Print time, file, line, func, message */
#ifdef DEBUG_PRINT
#define DEBUG_MSG(...) \
    do { \
        char _buf[MAX_DEBUG_LEN], *_p = _buf; \
        _p += snprintf_time(_p, sizeof(_buf)); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), "\t"); \
        _p += snprintf_file(_p, SIZE_REMAIN(_buf, _p), __FILE__); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), \
                " (line %d): %s() -- ", __LINE__, __FUNCTION__); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), __VA_ARGS__); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), "\n"); \
        write_log(_buf); \
    } while(0)
#else
#define DEBUG_MSG(...) do { } while(0)
#endif

/* Print time, ERROR_MSG:, file, line, func, message */
#ifdef ERROR_PRINT
#define ERROR_MSG(...) \
    do { \
        char _buf[MAX_DEBUG_LEN], *_p = _buf; \
        _p += snprintf_time(_p, sizeof(_buf)); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), "\tERROR_MSG: "); \
        _p += snprintf_file(_p, SIZE_REMAIN(_buf, _p), __FILE__); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), \
                " (line %d): %s() -- ", __LINE__, __FUNCTION__); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), __VA_ARGS__); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), \
                ": %s - Error #(%d)\n", strerror(errno), errno); \
        write_log(_buf); \
    } while(0)
#else
#define ERROR_MSG(...) do { } while(0)
#endif

/* Print message only */
#ifdef GENERAL_PRINT
#define GENERAL_MSG(...) \
    do { \
        char _buf[MAX_DEBUG_LEN]; \
        snprintf(_buf, sizeof(_buf), __VA_ARGS__); \
        write_log(_buf); \
    } while(0)
#else
#define GENERAL_MSG(...) do { } while(0)
#endif

/* Send time, message to log file */
#ifdef STATS_PRINT
#define STATS_MSG(...) \
    do { \
        char _buf[MAX_DEBUG_LEN], *_p = _buf; \
        _p += snprintf_time(_p, sizeof(_buf)); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), "\t"); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), __VA_ARGS__); \
        _p += snprintf(_p, SIZE_REMAIN(_buf, _p), "\n"); \
        writeStatsLog(_buf); \
    } while(0)
#else
#define STATS_MSG(...) do { } while(0)
#endif

/* Send message only to log file */
#ifdef STATUS_PRINT
#define STATS_BANNER(...) \
    do { \
        char _buf[MAX_DEBUG_LEN]; \
        snprintf(_buf, sizeof(_buf), __VA_ARGS__); \
        writeStatsLog(_buf); \
    } while(0)
#else
#define STATS_BANNER(...) do { } while(0)
#endif

/* Send stack backtrace to system log */
void log_backtrace(void);

/*
 * ASSERT_OR_ELSE adds additional functionality to the assert function.
 *
 * If NDEBUG is defined, as in a release version of the software,
 * ASSERT_OR_ELSE activates a body of code that can be used for graceful
 * recovery.  If NDEBUG is not defined, as in debugging versions, assert() will
 * be called as usual.  assert(expr) halts the program if expr evaluates to
 * false.  It also prints a helpful message telling you where the program
 * halted.
 *
 * Example usage:
 * ASSERT_OR_ELSE(important_pointer) {
 *     printf("The horror, we have a null pointer!\n");
 *     return -1;
 * }
 * (*important_pointer)++;
 *
 * If NDEBUG is defined, this code will never crash due to a null pointer.
 */
#ifdef NDEBUG
#define ASSERT_OR_ELSE(expr) if (!(expr))
#else
#define ASSERT_OR_ELSE(expr) assert(expr); if(0)
#endif

#endif //_DEBUG_H_

