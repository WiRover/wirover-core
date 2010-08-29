#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <assert.h>
#include <stdio.h>
#include <string.h> //for strerror

void print_time(FILE* out);

// Enable the  messages
#define DEBUG_PRINT
#define ERROR_PRINT

#ifdef DEBUG_PRINT
void __debug_msg(const char* msg, const char* file, int line, const char* func);
#define DEBUG_MSG(msg) __debug_msg(msg, __FILE__, __LINE__, __FUNCTION__);
#else
#define DEBUG_MSG
#endif

#ifdef ERROR_PRINT
void __error_msg(const char* msg, const char* file, int line, const char* func);
#define ERROR_MSG(msg) __error_msg(msg, __FILE__, __LINE__, __FUNCTION__);
#else
#define ERROR_MSG
#endif

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

#define HEX_CHAR(x) ((x < 0x0A) ? ('0' + x) : ('A' + x - 0x0A))
void to_hex_string(const char* __restrict__ src, int src_len,
                   char* __restrict__ dest, int dest_len);

#endif //_DEBUG_H_

