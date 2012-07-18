#include <assert.h>
#include <fcntl.h>
#include <asm-generic/sockios.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
//#include <stropts.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <netdb.h>

#include "debug.h"
#include "sockets.h"
#include "utlist.h"

/*
 * TCP PASSIVE OPEN
 *
 * local_port should be in host byte order.
 * Returns a valid socket file descriptor or -1 on failure.
 */
int tcp_passive_open(unsigned short local_port, int backlog)
{
    int sockfd = -1;

    sockfd = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if(sockfd < 0) {
        ERROR_MSG("failed creating socket");
        return -1;
    }

    // Prevent bind from failing in case the program was restarted.
    const int yes = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        DEBUG_MSG("SO_REUSEADDR failed");
        close(sockfd);
        return -1;
    }

    char portString[16];
    snprintf(portString, sizeof(portString), "%d", local_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_V4MAPPED | AI_NUMERICHOST | AI_PASSIVE;

    struct addrinfo* results = 0;
    int ret = getaddrinfo(0, portString, &hints, &results);
    if(ret != 0) {
        DEBUG_MSG("getaddrinfo() failed: %s", gai_strerror(ret));
        close(sockfd);
        return -1;
    }
    
    // If getaddrinfo completed successfully, these pointers should not be
    // null, so this assert should never be triggered
    assert(results != 0 && results->ai_addr != 0);

    if(bind(sockfd, results->ai_addr, results->ai_addrlen) < 0) {
        ERROR_MSG("failed binding socket");
        goto free_and_return;
    }

    if(listen(sockfd, backlog) < 0) {
        ERROR_MSG("failed to listen on socket");
        goto free_and_return;
    }
   
    freeaddrinfo(results);
    return sockfd;

free_and_return:
    freeaddrinfo(results);
    close(sockfd);
    return -1;
}

/*
 * TCP ACTIVE OPEN
 */
int tcp_active_open(const char* remote_addr, unsigned short remote_port,
        const char *device, struct timeval *timeout)
{
    int sockfd;
    int rtn;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_NUMERICSERV;

    char port_string[16];
    snprintf(port_string, sizeof(port_string), "%d", remote_port);

    struct addrinfo* results = 0;
    rtn = getaddrinfo(remote_addr, port_string, &hints, &results);
    if(rtn != 0) {
        DEBUG_MSG("getaddrinfo failed - %s", gai_strerror(rtn));
        return -1;
    }

    // If getaddrinfo completed successfully, these pointers should not be
    // null, so this assert should never be triggered
    assert(results != 0 && results->ai_addr != 0);

    sockfd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
    if(sockfd < 0) {
        ERROR_MSG("failed creating socket");
        goto free_and_return;
    }
    
    if(device) {
        // Bind socket to device
        if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, device, IFNAMSIZ) < 0) {
            ERROR_MSG("SO_BINDTODEVICE failed");
            goto close_and_return;
        }
    }

    if(timeout)
        set_nonblock(sockfd, NONBLOCKING);
    
    rtn = connect(sockfd, results->ai_addr, results->ai_addrlen);
    if(rtn == -1 && errno != EINPROGRESS) {
        ERROR_MSG("connect");
        goto close_and_return;
    }

    if(timeout) {
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(sockfd, &write_set);

        // sockfd will become writable if connect finishes before timeout
        rtn = select(sockfd + 1, 0, &write_set, 0, timeout);
        if(rtn < 0) {
            if(errno != EINTR)
                ERROR_MSG("select");
            goto close_and_return;
        } else if(rtn == 0) {
            DEBUG_MSG("connect timed out");
            goto close_and_return;
        }

        set_nonblock(sockfd, BLOCKING);
    }

    freeaddrinfo(results);
    return sockfd;

free_and_return:
    freeaddrinfo(results);
close_and_return:
    close(sockfd);
    return -1;
}

/*
 * Opens a UDP socket and binds it to the given port.  If device is non-null,
 * it also binds the socket to the device.
 */
int udp_bind_open(unsigned short local_port, const char* device)
{
    int sockfd;

    // getaddrinfo takes a string rather than an int
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", local_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    struct addrinfo* results = 0;
    int err = getaddrinfo(0, port_str, &hints, &results);
    if(err != 0) {
        DEBUG_MSG("getaddrinfo failed: %s", gai_strerror(err));
        return FAILURE;
    }

    sockfd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
    if(sockfd < 0) {
        ERROR_MSG("Failed to create socket");
        goto free_and_fail;
    }
    
    // Prevent bind from failing with address in use message.
    const int yes = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        DEBUG_MSG("SO_REUSEADDR failed");
        goto free_and_fail;
    }

    if(bind(sockfd, results->ai_addr, results->ai_addrlen) == -1) {
        ERROR_MSG("Failed to bind socket");
        goto free_and_fail;
    }
    
    if(device) {
        // Bind socket to device
        if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, device, IFNAMSIZ) < 0) {
            ERROR_MSG("SO_BINDTODEVICE failed");
            goto free_and_fail;
        }
    }

    freeaddrinfo(results);
    return sockfd;

free_and_fail:
    freeaddrinfo(results);
    close(sockfd);
    return FAILURE;

}

int connect_timeout(int socket, struct sockaddr *addr, socklen_t addrlen, 
                struct timeval *timeout)
{
    int         result;
    fd_set      writeSet;
    int         prevFlags;
    int         retval = 0;
    
    if(!timeout) {
        retval = connect(socket, addr, addrlen);
        goto done;
    }

    FD_ZERO(&writeSet);
    FD_SET(socket, &writeSet);

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
    result = select(socket + 1, 0, &writeSet, 0, timeout);
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
 * This is a wrapper function around recv that blocks for the specified maximum
 * amount of time.  Error reporting matches that of the recv function.  On
 * timeout, -1 is returned with errno set to EWOULDBLOCK.
 */
int recv_timeout(int sockfd, void *buffer, size_t len, int flags, 
                struct timeval *timeout)
{
    int res;
    fd_set read_set;
    int sock_flags;

    sock_flags = fcntl(sockfd, F_GETFL, 0);
    if(flags == -1) {
        ERROR_MSG("fcntl F_GETFL failed");
    }

    // Set socket to nonblocking for safety
    if(!(sock_flags & O_NONBLOCK)) {
        if(fcntl(sockfd, F_SETFL, (sock_flags | O_NONBLOCK) == -1)) {
            ERROR_MSG("fcntl F_SETFL failed");
        }
    }

    FD_ZERO(&read_set);
    FD_SET(sockfd, &read_set);

    res = select(sockfd + 1, &read_set, 0, 0, timeout);
    if(res < 0) {
        ERROR_MSG("select failed");
        return -1;
    } else if(!FD_ISSET(sockfd, &read_set)) {
        // timed out
        errno = EWOULDBLOCK;
        return -1;
    }

    res = recv(sockfd, buffer, len, flags);

    // Restore socket flags
    if(!(sock_flags & O_NONBLOCK)) {
        if(fcntl(sockfd, F_SETFL, sock_flags) == -1) {
            ERROR_MSG("fcntl F_SETFL failed");
        }
    }

    return res;
}

/*
 * This is a wrapper function around recvfrom that blocks for the specified maximum
 * amount of time.  Error reporting matches that of the recv function.  On
 * timeout, -1 is returned with errno set to EWOULDBLOCK.
 */
int recvfrom_timeout(int sockfd, void *buffer, size_t len, int flags, 
        struct sockaddr *address, socklen_t *address_len, struct timeval *timeout)
{
    int res;
    fd_set read_set;
    int sock_flags;

    sock_flags = fcntl(sockfd, F_GETFL, 0);
    if(flags == -1) {
        ERROR_MSG("fcntl F_GETFL failed");
    }

    // Set socket to nonblocking for safety
    if(!(sock_flags & O_NONBLOCK)) {
        if(fcntl(sockfd, F_SETFL, (sock_flags | O_NONBLOCK) == -1)) {
            ERROR_MSG("fcntl F_SETFL failed");
        }
    }

    FD_ZERO(&read_set);
    FD_SET(sockfd, &read_set);

    res = select(sockfd + 1, &read_set, 0, 0, timeout);
    if(res < 0) {
        ERROR_MSG("select failed");
        return -1;
    } else if(!FD_ISSET(sockfd, &read_set)) {
        // timed out
        errno = EWOULDBLOCK;
        return -1;
    }

    res = recvfrom(sockfd, buffer, len, flags, address, address_len);

    // Restore socket flags
    if(!(sock_flags & O_NONBLOCK)) {
        if(fcntl(sockfd, F_SETFL, sock_flags) == -1) {
            ERROR_MSG("fcntl F_SETFL failed");
        }
    }

    return res;
}

/*
 * SET NONBLOCK
 *
 * enable should be non-zero to set or 0 to clear.
 * Returns 0 on success or -1 on failure.
 */
int set_nonblock(int sockfd, int enable)
{
    int flags;

    flags = fcntl(sockfd, F_GETFL, 0);
    if(flags == -1) {
        ERROR_MSG("fcntl F_GETFL failed");
        return -1;
    }

    if(enable && !(flags & O_NONBLOCK)) {
        flags = flags | O_NONBLOCK;
        if(fcntl(sockfd, F_SETFL, flags) == -1) {
            ERROR_MSG("fcntl F_SETFL failed");
            return -1;
        }
    } else if(!enable && (flags & O_NONBLOCK)) {
        flags = flags & ~O_NONBLOCK;
        if(fcntl(sockfd, F_SETFL, flags) == -1) {
            ERROR_MSG("fcntl F_SETFL failed");
            return -1;
        }
    }

    return 0;
}

/*
 * BUILD SOCKADDR
 */
int build_sockaddr(const char* ip, unsigned short port, struct sockaddr_storage* dest)
{
    assert(ip && dest);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_NUMERICSERV;

    struct addrinfo* results = 0;
    int err;

    if(port > 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);

        err = getaddrinfo(ip, port_str, &hints, &results);
    } else {
        err = getaddrinfo(ip, 0, &hints, &results);
    }

    if(err != 0) {
        DEBUG_MSG("Failed to convert IP address %s: %s", ip, gai_strerror(err));
        return FAILURE;
    }

    memset(dest, 0, sizeof(*dest));
    memcpy(dest, results->ai_addr, results->ai_addrlen);
    freeaddrinfo(results);

    return results->ai_addrlen;
}

/*
 * FDSET ADD CLIENTS
 *
 * Adds every client in the linked list to the given fd_set and updates the
 * max_fd value.  Both of these operations are generally necessary before using
 * select().
 */
void fdset_add_clients(const struct client* head, fd_set* set, int* max_fd)
{
    assert(set && max_fd);

    while(head) {
        FD_SET(head->fd, set);

        if(head->fd > *max_fd) {
            *max_fd = head->fd;
        }

        assert(head != head->next);
        head = head->next;
    }
}

/*
 * HANDLE CONNECTION
 *
 * Accepts a client connection attempt and adds it to the linked list of
 * clients.
 */
void handle_connection(struct client** head, int server_sock)
{
    assert(head);

    struct client* client = (struct client*)malloc(sizeof(struct client));
    assert(client);

    client->addr_len = sizeof(client->addr);
    client->fd = accept(server_sock, (struct sockaddr*)&client->addr, &client->addr_len);
    if(client->fd == -1) {
        ERROR_MSG("accept() failed");
        free(client);
        return;
    }

    // All of our sockets will be non-blocking since they are handled by a
    // single thread, and we cannot have one evil client hold up the rest.
    set_nonblock(client->fd, 1);

    client->last_active = time(0);

    DL_APPEND(*head, client);
}

/*
 * HANDLE DISCONNECTION
 *
 * Removes a client from the linked list, closes its socket, and frees its
 * memory.
 */
void handle_disconnection(struct client** head, struct client* client)
{
    assert(head && client);

    close(client->fd);
    client->fd = -1;

    DL_DELETE(*head, client);
    free(client);
}

/*
 * REMOVE IDLE CLIENTS
 *
 * Drops connections that are idle.
 */
void remove_idle_clients(struct client** head, unsigned int timeout_sec)
{
    assert(head);

    time_t cutoff = time(0) - timeout_sec;

    struct client* client;
    struct client* tmp;

    DL_FOREACH_SAFE(*head, client, tmp) {
        if(client->last_active <= cutoff) {
            handle_disconnection(head, client);
        }
    }
}

void fill_buffer_random(void *buffer, int size)
{
    int i;

    const int num_words = size / sizeof(int);
    for(i = 0; i < num_words; i++)
        ((int *)buffer)[i] = rand();

    const int rem_bytes = size % sizeof(int);
    for(i = 1; i <= rem_bytes; i++)
        ((char *)buffer)[size - i] = (char)rand();
}

int get_recv_timestamp(int sockfd, struct timeval *timestamp) {
    if(ioctl(sockfd, SIOCGSTAMP, timestamp) < 0) {
        gettimeofday(timestamp, 0);
    }
    return 0;
}


