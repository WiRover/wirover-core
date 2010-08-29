#ifndef _SOCKETS_H_
#define _SOCKETS_H_

int tcp_passive_open(unsigned short local_port, int backlog);
int tcp_active_open(const char* remote_addr, unsigned short remote_port);
int set_nonblock(int sockfd, int enable);

#endif //_SOCKETS_H_

