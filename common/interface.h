#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include "uthash.h"

#define NETWORK_NAME_LENGTH 16

enum if_state {
    ACTIVE = 1,
    INACTIVE,
    DEAD
};

struct interface {
    unsigned int      index; //interface index assigned by kernel
    char              name[IFNAMSIZ];
    char              network[NETWORK_NAME_LENGTH];
    enum if_state     state;

    // default gateway for routing if needed
    char              gw_ip[INET6_ADDRSTRLEN];

    struct interface* next;
    struct interface* prev;
};

struct interface_iterator {
    struct interface* curr;
    struct interface* next;
};

struct interface* alloc_interface();
void free_interface(struct interface* ife);

//These are currently implemented by searching the linked list, since the list
//will typically contain around 1-3 elements.  One can very easily change
//these functions to use uthash if it helps.
struct interface* find_interface_by_index(struct interface* head, unsigned int index);
struct interface* find_interface_by_name(struct interface* head, const char* name);
struct interface* find_interface_by_network(struct interface* head, const char* network);

#endif //_INTERFACE_H_

