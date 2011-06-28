#ifndef _NETLINK_H_
#define _NETLINK_H_

#include "interface.h"

#define NETLINK_BUFFER_SIZE     4096

struct rwlock;

int init_interface_list();

int create_netlink_thread();
int wait_for_netlink_thread();

int open_netlink_socket();
int handle_netlink_message(const char* msg, int msg_len);

int change_interface_state(struct interface* ife, enum if_state state);

void read_network_name(const char * __restrict__ ifname, 
        char * __restrict__ dest, int destlen);

// All threads accessing the list need to lock and unlock it the rwlock.
extern struct interface*    interface_list;
extern struct rwlock        interface_list_lock;

#endif //_NETLINK_H_

