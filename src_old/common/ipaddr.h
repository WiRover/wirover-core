#ifndef WIROVER_IPADDR_H
#define WIROVER_IPADDR_H

#include <sys/socket.h>

// IPv6 addresses require 16 bytes in binary form.
// For the text representation, use the constant INET6_ADDRSTRLEN.
#define IPADDR_SIZE 16

struct ipaddr {
    unsigned char addr[IPADDR_SIZE];
} __attribute__((__packed__));

typedef struct ipaddr ipaddr_t;

#define IPADDR_IPV6_ZERO { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } }
#define IPADDR_IPV4_ZERO { { 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0xFF, 0xFF,  0x00, 0x00, 0x00, 0x00 } }

struct sockaddr;
struct sockaddr_in;

int     string_to_ipaddr(const char* addr, ipaddr_t* dest);
int     ipaddr_to_string(const ipaddr_t* addr, char* dest, unsigned len);
int     sockaddr_to_ipaddr(const struct sockaddr*, ipaddr_t* dest);
int     ipv4_to_ipaddr(uint32_t addr, ipaddr_t* dest);
int     ipaddr_to_ipv4(const ipaddr_t* addr, uint32_t* dest);
void    copy_ipaddr(const ipaddr_t* src, ipaddr_t* dest);
int     ipaddr_is_ipv4(const ipaddr_t *addr);

int ipaddr_cmp(const ipaddr_t *a, const ipaddr_t *b);

int get_interface_address(const char *dev, struct sockaddr *dest, int dest_len);
int resolve_address(const char *address, struct sockaddr *dest, int dest_len);

const char *sockaddr_ntop(const struct sockaddr *src, char *dst, socklen_t size);
unsigned short sockaddr_port(const struct sockaddr *addr);

int sockaddr_to_sockaddr_in(const struct sockaddr *src, 
        socklen_t src_len, struct sockaddr_in *dst);

#endif //WIROVER_IPADDR_H

