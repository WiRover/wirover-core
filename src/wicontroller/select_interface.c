#include <arpa/inet.h>
#include <linux/if.h>

#include "interface.h"
#include "debug.h"
#include "policy_table.h"
#include "sockets.h"
#include "tunnel.h"
#include "select_interface.h"
#include "remote_node.h"
#include "ipaddr.h"

int select_src_interface(struct flow_entry *fe, struct interface **dst, int size)
{
    dst[0] = interface_list;
    if(dst[0] != NULL)
        return 1;
    return 0;
}

int select_dst_interface(struct flow_entry *fe, struct interface **dst, int size)
{
    struct remote_node *gw = NULL;
    gw = lookup_remote_node_by_id(fe->egress.remote_node_id);
    //Case where a flow isn't inititated by a gateway
    if(gw == NULL) 
    {
        if(!fe->owner) return 0;

        ipaddr_t dst_ip;
        ipv4_to_ipaddr(fe->id->remote, &dst_ip);
        struct remote_node *node, *tmp;
        obtain_read_lock(&remote_node_lock);
        HASH_ITER(hh_id, remote_node_id_hash, node, tmp) 
        {
            if(ipaddr_cmp(&node->private_ip, &dst_ip) == 0){
                fe->egress.remote_node_id = node->unique_id;
                fe->ingress.remote_node_id = node->unique_id;
                dst[0] = find_active_interface(node->head_interface);
                break;
            }
        }
        release_read_lock(&remote_node_lock);
        if(dst[0] == NULL)
        {
            DEBUG_MSG("Dropping packet for uknown gateway");
            return 0;
        }
    }
    else if ((fe->egress.action & POLICY_ACT_MASK) == POLICY_ACT_ENCAP)
    {
        if (fe->egress.action & POLICY_OP_MULTIPATH) {
            dst[0] = select_mp_interface(gw->head_interface);
            return 1;
        }
        if((fe->egress.action & POLICY_OP_MASK) == POLICY_OP_DUPLICATE)
        {
            return select_all_interfaces(interface_list, dst, size);
        }

        dst[0] = find_interface_by_index(gw->head_interface, fe->egress.remote_link_id);
        if(dst[0] == NULL || dst[0]->state == INACTIVE)
        {
            dst[0] = find_active_interface(gw->head_interface);
        }
        return dst[0] != NULL;
    }
    return 0;
}

