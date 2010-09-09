#ifndef _SOCKETS_H_
#define _SOCKETS_H_

#include <sys/select.h>

struct client {
    int                 fd;
    struct sockaddr_in  addr;
    socklen_t           addr_len;
    time_t              last_active;

    // private
    struct client*      next;
    struct client*      prev;
};

//SOMAXCONN is a good value for backlog
int tcp_passive_open(unsigned short local_port, int backlog);
int tcp_active_open(const char* remote_addr, unsigned short remote_port);
int set_nonblock(int sockfd, int enable);

// Some generic TCP server functions
void fdset_add_clients(const struct client* head, fd_set* set, int* max_fd);
void handle_connection(struct client** head, int server_sock);
void handle_disconnection(struct client** head, struct client* client);
void remove_idle_clients(struct client** head, unsigned int timeout_sec);

#endif //_SOCKETS_H_

