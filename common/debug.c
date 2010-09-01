#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include "debug.h"

/*
 * PRINT TIME
 */
void print_time(FILE* out)
{
    struct timeval now;
    struct tm broken;

    gettimeofday(&now, 0);
    localtime_r(&now.tv_sec, &broken);

    fprintf(out, "%d/%02d/%02d %02d:%02d:%02d.%06d", broken.tm_mon+1, broken.tm_mday,
            broken.tm_year+1900, broken.tm_hour, broken.tm_min, broken.tm_sec, (int)now.tv_usec);
}

#ifdef DEBUG_PRINT
void __debug_msg(const char* file, int line, const char* func, const char* msg, ...)
{
    print_time(stdout);

    va_list args;
    char buffer[MAX_DEBUG_LEN];

    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    
    const char* split_file = strrchr(file, '/');
    if(!split_file) {
        // It was not a full path
        split_file = file;
    } else {
        // Ignore the leading '/'
        split_file++;
    }

    printf("\t%s (line %d): %s() -- %s\n", split_file, line, func, buffer);
}

void __error_msg(const char* file, int line, const char* func, const char* msg, ...)
{
    print_time(stdout);
    
    va_list args;
    char buffer[MAX_DEBUG_LEN];

    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);

    const char* split_file = strrchr(file, '/');
    if(!split_file) {
        // It was not a full path
        split_file = file;
    } else {
        // Ignore the leading '/'
        split_file++;
    }

    printf("\tERROR_MSG: %s (line %d): %s() -- %s: %s - Error #(%d)\n", split_file,
           line, func, buffer, strerror(errno), errno);
}
#endif //DEBUG_PRINT

void to_hex_string(const char* __restrict__ src, int src_len,
                   char* __restrict__ dest, int dest_len)
{
    if((2 * src_len + 1) > dest_len) {
        DEBUG_MSG("Source is too long for destination");
    }

    int s = 0;
    int d = 0;
    while(s < src_len && d < dest_len) {
        int high = (src[s] & 0xF0) >> 4;
        int low = (src[s] & 0x0F);

        dest[d++] = HEX_CHAR(high);
        dest[d++] = HEX_CHAR(low);
        s++;
    }

    // null terminate the string
    if(d < dest_len) {
        dest[d] = 0;
    } else {
        dest[dest_len-1] = 0;
    }
}

