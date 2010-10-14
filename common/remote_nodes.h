#ifndef _REMOTE_NODES_H_
#define _REMOTE_NODES_H_

#include <stdint.h>
#include "ipaddr.h"

// Locations of proc files
#define PROC_FILE_REMOTE_NODES "/proc/virtmod/remote/nodes"
#define PROC_FILE_REMOTE_LINKS "/proc/virtmod/remote/links"

#define PROC_REMOTE_ADD     0
#define PROC_REMOTE_DELETE  1

struct virt_proc_remote_node {
    unsigned    op;
    ipaddr_t    priv_ip;
    uint16_t    base_port;
} __attribute__((__packed__));

struct virt_proc_remote_link {
    unsigned    op;

    // priv_ip identifies the node to which this link belongs, so the node must
    // be added before a link is added.
    ipaddr_t    priv_ip;
    ipaddr_t    pub_ip;
} __attribute__((__packed__));

int change_remote_node_table(struct virt_proc_remote_node* change);
int change_remote_link_table(struct virt_proc_remote_link* change);

#endif //_REMOTE_NODES_H_

