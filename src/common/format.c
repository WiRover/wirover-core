#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "format.h"

/*
 * Convert binary data into a null-terminated hexadecimal string.
 *
 * Returns the length of the resulting string (excluding the null byte) or a
 * negative value if an error occurred.
 */
int bin_to_hex(const char *src, int srclen, char *dst, int dstlen)
{
    if(dstlen < (2 * srclen + 1))
        return -1;

    int s = 0;
    int d = 0;

    while(s < srclen) {
        char high = (src[s] & 0xF0) >> 4;
        char low = (src[s] & 0x0F);

        dst[d++] = HEX_CHAR(high);
        dst[d++] = HEX_CHAR(low);
        s++;
    }

    dst[d] = 0;

    return d;
}

/*
 * Interpret the ASCII character c as a hexadecimal digit.
 *
 * Returns 0-16 for a hexadecimal digit or -1 for and invalid character.
 */
char hex_char_val(char c)
{
    if(c >= '0' && c <= '9') {
        return (c - '0');
    } else if(c >= 'a' && c <= 'f') {
        return (c - 'a' + 10);
    } else if(c >= 'A' && c <= 'F') {
        return (c - 'A' + 10);
    } else {
        return -1;
    }
}

/*
 * Convert a hexadecimal string to binary data.  Conversion stops at the first
 * null byte or after srclen bytes.
 *
 * Returns the size (in bytes) of the result or a negative error code.
 *
 * -1 : dst is too small to hold the result
 * -2 : The string contains invalid characters.
 */
int hex_to_bin(const char *src, int srclen, char *dst, int dstlen)
{
    /* Check if the string terminates early. */
    srclen = strnlen(src, srclen);

    if(2 * dstlen < srclen)
        return -1;

    int s = 0;
    int d = 0;

    /* If the string has odd length, handle the first character as if it had a
     * zero in front of it. */
    if(srclen % 2) {
        char low = hex_char_val(src[s++]);
        if(low < 0)
            return -2;
        dst[d++] = low;
    }

    while(s+1 < srclen) {
        char high = hex_char_val(src[s++]);
        char low = hex_char_val(src[s++]);

        if(high < 0 || low < 0)
            return -2;
        
        dst[d++] = (high << 4) | low;
    }

    return d;
}

