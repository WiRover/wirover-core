#ifndef WIROVER_IPADDR_H
#define WIROVER_IPADDR_H

// IPv6 addresses require 16 bytes in binary form.
// For the text representation, use the constant INET6_ADDRSTRLEN.
#define IPADDR_SIZE     16

struct ipaddr {
    unsigned char   addr[IPADDR_SIZE];
} __attribute__((__packed__));

typedef struct ipaddr   ipaddr_t;

#define IPADDR_INITIALIZER { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } }

struct sockaddr;

int     string_to_ipaddr(const char* addr, ipaddr_t* dest);
int     ipaddr_to_string(const ipaddr_t* addr, char* dest, unsigned len);
int     sockaddr_to_ipaddr(const struct sockaddr*, ipaddr_t* dest);
int     ipv4_to_ipaddr(uint32_t addr, ipaddr_t* dest);
int     ipaddr_to_ipv4(const ipaddr_t* addr, uint32_t* dest);
void    copy_ipaddr(const ipaddr_t* src, ipaddr_t* dest);

#endif //WIROVER_IPADDR_H

