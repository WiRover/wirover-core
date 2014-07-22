#include <arpa/inet.h>

#include "interface.h"
#include "debug.h"
#include "sockets.h"
#include "tunnel.h"
#include "select_interface.h"
#include "remote_node.h"

struct interface *select_src_interface(struct flow_entry *fe)
{
    return interface_list;
}

struct interface *select_dst_interface(struct flow_entry *fe)
{
    if(fe == NULL) {
        DEBUG_MSG("Dropping packet for uknown gateway");
    }
    struct remote_node *gw;
    gw = lookup_remote_node_by_id(fe->node_id);
    if(gw == NULL) {
        DEBUG_MSG("Dropping packet destined for unknown gateway");
        return NULL;
    }
    return find_interface_by_index(gw->head_interface, fe->link_id);
}			
