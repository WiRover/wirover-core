#ifndef _NETLINK_H_
#define _NETLINK_H_

#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>

#define NETWORK_NAME_LENGTH 16

enum if_state {
    ACTIVE = 1,
    INACTIVE,
    DEAD
};

struct interface {
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

int init_interface_list();
struct interface* create_interface(const char* name);

/*
 * These locking functions if used properly restrict access to the interface
 * list to either:
 *   1. All readers, concurrently
 *   2. One writer
 */
struct interface* obtain_read_lock();
struct interface* obtain_write_lock();
void release_read_lock();
void release_write_lock();

#endif //_NETLINK_H_

