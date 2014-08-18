#include <arpa/inet.h>
#include <linux/if.h>

#include "interface.h"
#include "debug.h"
#include "sockets.h"
#include "tunnel.h"
#include "select_interface.h"
#include "remote_node.h"
#include "ipaddr.h"

struct interface *select_src_interface(struct flow_entry *fe)
{
    return interface_list;
}

struct interface *select_dst_interface(struct flow_entry *fe)
{
    struct remote_node *gw;
    struct interface * dst_ife;
    gw = lookup_remote_node_by_id(fe->remote_node_id);
    //Case where a flow isn't inititated by a gateway
    if(gw == NULL) 
    {
        ipaddr_t dst_ip;
        ipv4_to_ipaddr(fe->id->dAddr, &dst_ip);
        struct remote_node *node, *tmp;
        HASH_ITER(hh_id, remote_node_id_hash, node, tmp) 
        {
            if(ipaddr_cmp(&node->private_ip, &dst_ip) == 0){
                dst_ife = find_active_interface(node->head_interface);
            }
        }
        if(dst_ife == NULL)
        {
            DEBUG_MSG("Dropping packet for uknown gateway");
            return NULL;
        }
    }
    else
    {
        dst_ife = find_interface_by_index(gw->head_interface, fe->remote_link_id);
        if(dst_ife == NULL || dst_ife->state == INACTIVE)
        {
            dst_ife = find_active_interface(gw->head_interface);
        }
    }
    if(dst_ife != NULL) { fe->remote_link_id = dst_ife->index; }
    return dst_ife;
}
