#include <assert.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include <linux/if.h>

#include "ipaddr.h"
#include "debug.h"

const unsigned char IPV4_ON_IPV6_PREFIX[] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff,
    // IPv4 address goes here.
};

#define IPADDR_IPV4_OFFSET (sizeof(IPV4_ON_IPV6_PREFIX))

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

    if(ipaddr_is_ipv4(addr)) {
        if(!inet_ntop(AF_INET, addr->addr + IPADDR_IPV4_OFFSET, dest, len))
            return -1;
    } else {
        if(!inet_ntop(AF_INET6, addr->addr, dest, len))
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

    if(ipaddr_is_ipv4(addr)) {
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

int ipaddr_is_ipv4(const ipaddr_t *addr)
{
    return memcmp(addr->addr, IPV4_ON_IPV6_PREFIX, sizeof(IPV4_ON_IPV6_PREFIX)) == 0;
}

int ipaddr_cmp(const ipaddr_t *a, const ipaddr_t *b)
{
    return memcmp(a->addr, b->addr, IPADDR_SIZE);
}

int get_interface_address(const char *dev, struct sockaddr *dest, int dest_len)
{
    struct ifaddrs *ifap_head = NULL;
    struct ifaddrs *ifap = NULL;

    if(getifaddrs(&ifap_head) < 0) {
        ERROR_MSG("getifaddrs failed");
        return -1;
    }

    ifap = ifap_head;
    while(ifap) {
        if(strncmp(dev, ifap->ifa_name, IFNAMSIZ) == 0) {
            switch(ifap->ifa_addr->sa_family) {
                case AF_INET:
                {
                    if(dest_len >= sizeof(struct sockaddr_in)) {
                        memcpy(dest, ifap->ifa_addr, sizeof(struct sockaddr_in));
                        goto success_out;
                    }
                    break;
                }
                case AF_INET6:
                {
                    // TODO: Probably need to handle different address scopes
                    if(dest_len >= sizeof(struct sockaddr_in6)) {
                        memcpy(dest, ifap->ifa_addr, sizeof(struct sockaddr_in6));
                        goto success_out;
                    }
                }
            }
        }

        ifap = ifap->ifa_next;
    }

    freeifaddrs(ifap_head);
    return -1;

success_out:
    freeifaddrs(ifap_head);
    return 0;
}

/*
 * Resolve address which may be an interface name, an IP string,
 * or a hostname.
 */
int resolve_address(const char *address, struct sockaddr *dest, int dest_len)
{
    if(get_interface_address(address, dest, dest_len) == 0)
        return 0;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    if(dest_len >= sizeof(struct sockaddr_in6))
        hints.ai_family = AF_UNSPEC;
    else
        hints.ai_family = AF_INET;

    struct addrinfo *addrinfo;

    int result = getaddrinfo(address, 0, &hints, &addrinfo);
    if(result != 0) {
        DEBUG_MSG("getaddrinfo failed: %s", gai_strerror(result));
        return -1;
    }

    if(addrinfo->ai_addrlen <= dest_len) {
        memcpy(dest, addrinfo->ai_addr, addrinfo->ai_addrlen);
        freeaddrinfo(addrinfo);
        return 0;
    } else {
        freeaddrinfo(addrinfo);
        return -1;
    }
}

/*
 * Produces a human-readable IP address string from sockaddr structure.
 */
const char *sockaddr_ntop(const struct sockaddr *src, char *dst, socklen_t size)
{
    switch(src->sa_family) {
        case AF_INET:
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)src;
                return inet_ntop(AF_INET, &sin->sin_addr, dst, size);
            }
        case AF_INET6:
            {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src;
                return inet_ntop(AF_INET6, &sin6->sin6_addr, dst, size);
            }
    }

    return NULL;
}

/*
 * Returns port from sockaddr structure in host byte order.
 */
unsigned short sockaddr_port(const struct sockaddr *addr)
{
    switch(addr->sa_family) {
        case AF_INET:
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)addr;
                return ntohs(sin->sin_port);
            }
        case AF_INET6:
            {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
                return ntohs(sin6->sin6_port);
            }
    }

    return 0;
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


