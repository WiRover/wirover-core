#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include <time.h>
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
    int               priority;

    /* These are in network byte order. */
    struct in_addr    public_ip;
    uint16_t          data_port;

    time_t            last_ping;

    uint32_t    next_ping_seq_no;
    uint32_t    last_ping_seq_no;

    double            avg_rtt;

    // default gateway for routing if needed
    struct in_addr    gateway_ip;

    struct interface* next;
    struct interface* prev;
};

struct interface_copy {
    char    name[IFNAMSIZ];
};

struct interface* alloc_interface();
void free_interface(struct interface* ife);

//These are currently implemented by searching the linked list, since the list
//will typically contain around 1-3 elements.  One can very easily change
//these functions to use uthash if it helps.
struct interface* find_interface_by_index(struct interface* head, unsigned int index);
struct interface* find_interface_by_name(struct interface* head, const char* name);
struct interface* find_interface_by_network(struct interface* head, const char* network);

int count_active_interfaces(const struct interface *head);

struct interface *find_active_interface(struct interface *head);
int copy_active_interfaces(const struct interface *head, struct interface_copy **out);

double ema_update(double old_val, double new_val, double new_weight);

#endif //_INTERFACE_H_

