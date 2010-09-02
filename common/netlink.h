#ifndef _NETLINK_H_
#define _NETLINK_H_

#include <linux/if.h>

struct interface {
    char name[IFNAMSIZ];

    struct interface* next;
    struct interface* prev;
};

int init_interface_list();
struct interface* create_interface(const char* name);

#endif //_NETLINK_H_

