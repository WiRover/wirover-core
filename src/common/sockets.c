#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

// The following satisfy requirements for utils.h
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include "sockets.h"
#include "parameters.h"
#include "../common/debug.h"
#include "time_utils.h"
#include "utils.h"


/*
 * This is a wrapper function for connect() that is guaranteed to block for at
 * most the amount of time specified by the timeout parameter.
 */
int connect_timeout(int socket, struct sockaddr* addr, socklen_t addrlen, struct timespec* timeout)
{
    int         result;
    fd_set      writeSet;
    sigset_t    sigset;
    int         prevFlags;
    int         retval = 0;
    
    if(!timeout) {
        retval = connect(socket, addr, addrlen);
        goto done;
    }

    FD_ZERO(&writeSet);
    FD_SET(socket, &writeSet);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);

    prevFlags = fcntl(socket, F_GETFL, 0);
    if(prevFlags < 0) {
        ERROR_MSG("Failed to get file flags from socket");
        retval = -1;
        goto done;
    }

    // If the socket was not already set to nonblocking, we need to do so to
    // prevent connect() from blocking.
    if(prevFlags & ~O_NONBLOCK) {
        if(fcntl(socket, F_SETFL, prevFlags | O_NONBLOCK) < 0) {
            ERROR_MSG("Failed to set file flags on socket");
            retval = -1;
            goto done;
        }
    }

    // connect() should return -1 with errno set to EINPROGRESS
    result = connect(socket, addr, addrlen);
    if(result < 0 && errno != EINPROGRESS) {
        ERROR_MSG("Socket connect failed");
        retval = -1;
        goto reset_socket;
    }

    // If the socket becomes writable, then the connection attempt succeeded.
    result = pselect(socket + 1, 0, &writeSet, 0, timeout, &sigset);
    if(result < 0) {
        retval = -1;
        goto reset_socket;
    } else if(!FD_ISSET(socket, &writeSet)) {
        // Connection timed out
        errno = EWOULDBLOCK;
        retval = -1;
        goto reset_socket;
    }

reset_socket:    
    if(prevFlags & ~O_NONBLOCK) {
        if(fcntl(socket, F_SETFL, prevFlags) < 0) {
            ERROR_MSG("Failed to set file flags on socket");
            retval = -1;
        }
    }

done:
    return retval;

}

/*
 * This is a wrapper function for recv() that is guaranteed to block for at
 * most the amount of time specified by the timeout parameter.  Under unusual
 * circumstances(*), it may block for twice the specified time but not longer.
 *
 * The recvTime parameter is optional.  If non-null, recv_timeout() will write
 * into it the elapsed time of only the recv() system call.  Timing of recv()s
 * is useful for estimating bandwidth.
 *
 * (*) I think this may happen if the kernel drops the packet that we would
 * have received.  It may still cause select() to return and indicate the
 * availability of a packet, yet recv() will block because the packet is not
 * there.  We set the SO_RCVTIMEO socket option for the duration of
 * recv_timeout() to prevent recv() from blocking indefinitely in this
 * situation.
 */

int recv_timeout(int socket, void* buffer, size_t len, int flags, struct timespec* timeout, struct timeval* recvTime)
{
    int         result;
    fd_set      readSet;
    sigset_t    sigset;
    int         retval = 0;
    
    if(!timeout) {
        retval = recv(socket, buffer, len, flags);
        goto done;
    }

    FD_ZERO(&readSet);
    FD_SET(socket, &readSet);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);

    result = pselect(socket + 1, &readSet, 0, 0, timeout, &sigset);
    if(result < 0) {
        retval = -1;
        goto done;
    } else if(!FD_ISSET(socket, &readSet)) {
        // Receive timed out
        errno = EWOULDBLOCK;
        retval = -1;
        goto done;
    }
    
    struct timeval  prevRecvTimeout;
    struct timeval  tempRecvTimeout = {
        .tv_sec     = timeout->tv_sec,
        .tv_usec    = timeout->tv_nsec / 1000,
    };

    //TODO: Check return values of {get,set}sockopt()
    socklen_t       timeoutSize = sizeof(prevRecvTimeout);
    getsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, &timeoutSize);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tempRecvTimeout, sizeof(tempRecvTimeout));

    struct timeval  startTime;
    if(recvTime) {
        gettimeofday(&startTime, 0);
    }

    retval = recv(socket, buffer, len, flags);

    struct timeval  endTime;
    if(recvTime) {
        gettimeofday(&endTime, 0);
        timeval_diff(recvTime, &startTime, &endTime);
    }

    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, sizeof(prevRecvTimeout));

done:
    return retval;

}

int recvfrom_timeout(int socket, void* buffer, size_t len, int flags, struct timespec* timeout, struct timeval* recvTime)
{
    int         result;
    fd_set      readSet;
    sigset_t    sigset;
    int         retval = 0;
    
    if(!timeout) {
        retval = recvfrom(socket, buffer, len, flags, NULL, 0);
        goto done;
    }

    FD_ZERO(&readSet);
    FD_SET(socket, &readSet);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);

    result = pselect(socket + 1, &readSet, 0, 0, timeout, &sigset);
    //DEBUG_MSG("pselect result:%d",result);

    if(result < 0) {
        retval = -1;
        goto done;
    } else if(!FD_ISSET(socket, &readSet)) {
        // Receive timed out
        errno = EWOULDBLOCK;
        retval = -1;
        goto done;
    }
    
    struct timeval  prevRecvTimeout;
    struct timeval  tempRecvTimeout = {
        .tv_sec     = timeout->tv_sec,
        .tv_usec    = timeout->tv_nsec / 1000,
    };

    //TODO: Check return values of {get,set}sockopt()
    socklen_t       timeoutSize = sizeof(prevRecvTimeout);
    getsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, &timeoutSize);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tempRecvTimeout, sizeof(tempRecvTimeout));

    struct timeval  startTime;
    if(recvTime) {
        gettimeofday(&startTime, 0);
    }

    retval = recvfrom(socket, buffer, len, flags, NULL, 0);
    DEBUG_MSG("retval recvfrom:%d",retval);

    struct timeval  endTime;
    if(recvTime) {
        gettimeofday(&endTime, 0);
        timeval_diff(recvTime, &startTime, &endTime);
    }

    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, sizeof(prevRecvTimeout));

done:
    return retval;

}


/*
 * Find the transport layer header in a IPv4 or IPv6 packet.
 *
 * Returns -1 if the packet is invalid, otherwise returns the protocol and sets
 * *offset to the offset of the transport header.  This does not check the
 * validity of the transport header itself.
 *
 * In the case of IPPROTO_NONE, *offset is set to zero, but the packet is still
 * valid.
 *
 * data is expected to point to the beginning of the IP header, and len is is
 * expected to be the number of bytes in the packet starting from data.
 */
int find_transport_header(const char *data, unsigned len, int *offset)
{
    if(len < 1) {
        return -1;
    }

    const struct iphdr *iphdr = (const struct iphdr *)data;
    if(iphdr->version == 4) {
        unsigned hdrlen = iphdr->ihl * 4;
        if(hdrlen < len) {
            *offset = hdrlen;
            return iphdr->protocol;
        }
    } else if(iphdr->version == 6) {
        unsigned tmp_offset = sizeof(struct ip6_hdr);
        const struct ip6_hdr *ip6_hdr = (const struct ip6_hdr *)iphdr;
        unsigned char nexthdr = ip6_hdr->ip6_nxt;

        while(tmp_offset < len) {
            if(nexthdr == IPPROTO_HOPOPTS ||
                    nexthdr == IPPROTO_ROUTING ||
                    nexthdr == IPPROTO_FRAGMENT ||
                    nexthdr == IPPROTO_DSTOPTS) {
                nexthdr = data[tmp_offset];
                tmp_offset += data[tmp_offset + 1];
            } else if(nexthdr == IPPROTO_NONE) {
                *offset = 0;
                return nexthdr;
            } else {
                *offset = tmp_offset;
                return nexthdr;
            }
        }
    } else {
        DEBUG_MSG("Unrecognized ip version field (%u)", iphdr->version);
    }

    // Invalid packet
    return -1;
}


/*
 * F I L L   B U F F E R   R A N D O M
 *
 * Fills the buffer with random bytes.  Make sure you call srand somewhere.
 */
void fillBufferRandom(char* buffer, int numBytes)
{
    int* intBuffer = (int*)buffer;
    int ind;

    const int numWords = numBytes / sizeof(int);
    for(ind = 0; ind < numWords; ind++) {
        intBuffer[ind] = rand();
    }

    const int remBytes = numBytes % sizeof(int);
    switch(remBytes) {
    case 3:
        buffer[numBytes-3] = (char)rand();
    case 2:
        buffer[numBytes-2] = (char)rand();
    case 1:
        buffer[numBytes-1] = (char)rand();
    }
}


