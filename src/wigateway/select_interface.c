#include <arpa/inet.h>
#include <math.h>
#include "interface.h"
#include "debug.h"
#include "policy_table.h"
#include "remote_node.h"
#include "rootchan.h"
#include "select_interface.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"


int select_src_interface(struct flow_entry *fe, struct interface **dst, int size)
{
    assert(size > 0);
    if (fe->egress.link_select == POLICY_LS_MULTIPATH) {
        dst[0] = select_mp_interface(interface_list);
        return 1;
    }
    if(fe->egress.link_select == POLICY_LS_DUPLICATE)
    {
        return select_all_interfaces(interface_list, dst, size);
    }

    dst[0] = find_interface_by_index(interface_list, fe->egress.local_link_id);

    // In the case of NAT, we only assign an interface if we haven't already,
    // no failover occurs.
    if(fe->egress.action == POLICY_ACT_NAT) {
        if(fe->egress.local_link_id == 0){
            dst[0] = select_wrr_interface(interface_list);
            if(dst[0] != NULL)
                fe->egress.local_link_id = dst[0]->index;
        }
        return dst[0] != NULL;
    }
    else if(fe->egress.action == POLICY_ACT_ENCAP) {
        //Single interface case
        int max_priority = max_active_interface_priority(interface_list);
        if(dst[0] == NULL || dst[0]->state != ACTIVE || dst[0]->priority < max_priority)
        {
            dst[0] = select_wrr_interface(interface_list);
            if(dst[0] != NULL)
            {
                if(fe->owner) {
                    fe->requires_flow_info++;
                    fe->egress.local_link_id = dst[0]->index;
                    fe->ingress.local_link_id = dst[0]->index;
                }
                return 1;
            }
        }
        else { return 1; }
    }
    return 0;
}
int select_dst_interface(struct flow_entry *fe, struct interface **dst, int size)
{
    dst[0] = get_controller_ife();
    if(dst[0] != NULL) {
        if(fe->owner) {
            fe->ingress.remote_link_id = dst[0]->index;
            fe->egress.remote_link_id = dst[0]->index;
        }
        return 1;
    }
    return 0;
}