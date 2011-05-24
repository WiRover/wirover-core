#include <assert.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ipaddr.h"

const unsigned char IPV4_ON_IPV6_PREFIX[] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff,
    // IPv4 address goes here.
};

int string_to_ipaddr(const char* addr, ipaddr_t* dest)
{
    assert(dest);
    if(!dest) {
        return -1;
    }

    assert(addr);
    if(!addr) {
        memset(dest->addr, 0, sizeof(dest->addr));
        return 0;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_V4MAPPED; //map v4 addresses to v6

    int ret;
    struct addrinfo* results = 0;
    ret = getaddrinfo(addr, 0, &hints, &results);
    if(ret != 0) {
        return ret;
    }

    // If getaddrinfo completed successfully, these pointers should not be
    // null, so this assert should never be triggered
    assert(results != 0 && results->ai_addr != 0);

    // We asked for IPv6, so that's what we should get.
    assert(results->ai_family == AF_INET6);

    struct sockaddr_in6* saddr = (struct sockaddr_in6*)results->ai_addr;
    memcpy(dest->addr, &saddr->sin6_addr, sizeof(dest->addr));

    // Forgetting to free the results causes serious memory leakage.  We
    // learned that the hard way.
    freeaddrinfo(results);

    return 0;
}

int ipaddr_to_string(const ipaddr_t* addr, char* dest, unsigned len)
{
    assert(dest);
    if(!dest) {
        return -1;
    }

    assert(addr);
    if(!addr) {
        memset(dest, 0, len);
        return 0;
    }

    if(!inet_ntop(AF_INET6, addr->addr, dest, len)) {
        return -1;
    }

    return 0;
}

int sockaddr_to_ipaddr(const struct sockaddr* saddr, ipaddr_t* dest)
{
    assert(saddr && dest);
    if(!dest) {
        return -1;
    }

    if(!saddr) {
        memset(dest, 0, sizeof(*dest));
        return -1;
    }
    
    if(saddr->sa_family == AF_INET) {
        // We need to create an IPv4-mapped-to-IPv6 address.
        const struct sockaddr_in* tmp = (const struct sockaddr_in*)saddr;
        return ipv4_to_ipaddr(tmp->sin_addr.s_addr, dest);
    } else if(saddr->sa_family == AF_INET6) {
        // This is easy, just copy the IPv6 into dest.
        const struct sockaddr_in6* tmp = (const struct sockaddr_in6*)saddr;
        memcpy(dest->addr, tmp->sin6_addr.s6_addr, sizeof(dest->addr));
    } else {
        // Unrecognized socket family...
        return -1;
    }

    return 0;
}

int ipv4_to_ipaddr(uint32_t addr, ipaddr_t* dest)
{
    assert(dest);
    if(!dest) {
        return -1;
    }

    memcpy(dest->addr, IPV4_ON_IPV6_PREFIX, sizeof(IPV4_ON_IPV6_PREFIX));
    memcpy(dest->addr + sizeof(IPV4_ON_IPV6_PREFIX), &addr, sizeof(addr));

    return 0;
}

/*
 * Please try not to rely on this function, as it means the calling code is
 * incompatible with IPv6.
 *
 * Returns -1 if the ipaddr cannot be represented in v4.
 */
int ipaddr_to_ipv4(const ipaddr_t* addr, uint32_t* dest)
{
    assert(addr && dest);
    if(!addr || !dest) {
        return -1;
    }

    if(memcmp(addr->addr, IPV4_ON_IPV6_PREFIX, sizeof(IPV4_ON_IPV6_PREFIX)) == 0) {
        memcpy(dest, addr->addr + sizeof(IPV4_ON_IPV6_PREFIX), sizeof(*dest));
    } else {
        // The address is not an IPv4 address!
        return -1;
    }

    return 0;
}

void copy_ipaddr(const ipaddr_t* src, ipaddr_t* dest)
{
    assert(src && dest);

    if(dest && src) {
        memcpy(dest, src, sizeof(*dest));
    } else if(dest) {
        memset(dest, 0, sizeof(*dest));
    }
}

/* Copy from a generic sockaddr structure to a sockaddr_in structure.  If the
 * source is already a sockaddr_in, then this always succeeds.  If the source
 * is a sockaddr_in6, this is possible only if the address is an IPv4 mapped to
 * IPv6 address.  Returns 0 on success and -1 on failure. */
int sockaddr_to_sockaddr_in(const struct sockaddr *src,               
                socklen_t src_len, struct sockaddr_in *dst)
{
    if(src->sa_family == AF_INET && src_len == sizeof(struct sockaddr_in)) {
        memcpy(dst, src, sizeof(struct sockaddr_in));
        return 0;
    } else if(src->sa_family == AF_INET6 && 
            src_len == sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src;

        if(memcmp(sin6->sin6_addr.s6_addr, IPV4_ON_IPV6_PREFIX, 
                    sizeof(IPV4_ON_IPV6_PREFIX)) == 0) {
            memset(dst, 0, sizeof(*dst));
            dst->sin_family = AF_INET;
            dst->sin_port   = sin6->sin6_port;
            memcpy(&dst->sin_addr.s_addr, sin6->sin6_addr.s6_addr + 
                    sizeof(IPV4_ON_IPV6_PREFIX), sizeof(dst->sin_addr.s_addr));
            return 0;
        }
    }

    return -1;
}


