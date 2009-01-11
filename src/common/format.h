#ifndef FORMAT_H
#define FORMAT_H

#define HEX_CHAR(x) ((x < 0x0A) ? ('0' + x) : ('A' + x - 0x0A))

int bin_to_hex(const char *src, int srclen, char *dst, int dstlen);

char hex_char_val(char c);
int hex_to_bin(const char *src, int srclen, char *dst, int dstlen);

#endif /* FORMAT_H */

