#ifndef _SOCKETS_H_
#define _SOCKETS_H_

struct timespec;
struct timeval;

void fillBufferRandom(char* buffer, int numBytes); 

int connect_timeout(int socket, struct sockaddr* addr, socklen_t addrlen, 
        struct timespec* timeout);
int recv_timeout(int socket, void* buffer, size_t len, int flags, 
        struct timespec* timeout, struct timeval* recvTime);
int recvfrom_timeout(int socket, void* buffer, size_t len, int flags, 
        struct timespec* timeout, struct timeval* recvTime);

// Find the transport layer header in an IPv4/6 packet
int find_transport_header(const char *data, unsigned len, int *offset);

#endif //_SOCKETS_H_

