#include <assert.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ipaddr.h"

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

    memset(dest->addr, 0x00, 10);      // The first ten octets are filled with zeros.
    memset(dest->addr + 10, 0xff, 2);  // The next two octets are filled with ones.
    memcpy(dest->addr + 12, &addr, 4); // Then the IPv4 address.

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

