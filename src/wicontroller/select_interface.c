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
    gw = lookup_remote_node_by_id(fe->remote_node_id);
    //Case where a flow isn't inititated by a gateway
    if(gw == NULL) {
        ipaddr_t dst_ip;
        ipv4_to_ipaddr(fe->id->dAddr, &dst_ip);
        struct remote_node *node, *tmp;
        HASH_ITER(hh_id, remote_node_id_hash, node, tmp) {
            if(ipaddr_cmp(&node->private_ip, &dst_ip) == 0){
                struct interface *remote_ife = find_active_interface(node->head_interface);
                if(remote_ife != NULL) { fe->remote_link_id = remote_ife->index; }
                return remote_ife;
            }
        }
    }
    if(gw == NULL) {
        DEBUG_MSG("Dropping packet destined for unknown gateway");
        return NULL;
    }
    struct interface * dst_ife = find_interface_by_index(gw->head_interface, fe->remote_link_id);
    if(dst_ife->state == INACTIVE)
    {
        dst_ife = find_active_interface(gw->head_interface);
    }
    return dst_ife;
}			
