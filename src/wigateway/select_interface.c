#include <arpa/inet.h>
#include <math.h>
#include "interface.h"
#include "debug.h"
#include "policy_table.h"
#include "remote_node.h"
#include "rootchan.h"
#include "select_interface.h"
#include "state.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"


int select_src_interface(struct flow_entry *fe, struct interface **dst, int size)
{
    DEBUG_MSG("State: %d", state);
    assert(size > 0);
    dst[0] = NULL;
    // Multipath polices are only valid for the ENCAP action
    if(fe->egress.action == POLICY_ACT_ENCAP) {
        if (fe->egress.link_select == POLICY_LS_MULTIPATH) {
            dst[0] = select_mp_interface(interface_list);
            return 1;
        }
        else if(fe->egress.link_select == POLICY_LS_DUPLICATE)
        {
            return select_all_interfaces(interface_list, dst, size);
        }
    }

    // We are now selecting a single interface for either ENCAP or NAT

    // Assign an interface if we haven't already
    if(fe->egress.local_link_id == 0)
    {
        //Set both the ingress and egress preferred links if they exist
        struct interface *preferred_link;

        preferred_link = select_preferred_interface(interface_list, fe, DIR_INGRESS);
        if(preferred_link != NULL)
            fe->ingress.local_link_id = preferred_link->index;

        preferred_link = select_preferred_interface(interface_list, fe, DIR_EGRESS);
        if(preferred_link != NULL)
        {
            fe->egress.local_link_id = preferred_link->index;
            dst[0] = preferred_link;
        }

        if(dst[0] == NULL && fe->egress.link_select == POLICY_LS_WEIGHTED)
        {
            dst[0] = select_weighted_interface(interface_list);
            if(dst[0] != NULL)
            {
                fe->egress.local_link_id = dst[0]->index;
                fe->ingress.local_link_id = dst[0]->index;
            }
        }
        return dst[0] != NULL;
    }
    // Lookup the currently assigned interface and return if we don't need
    // failover
    dst[0] = find_interface_by_index(interface_list, fe->egress.local_link_id);
    if(fe->egress.action == POLICY_ACT_NAT || fe->egress.link_select == POLICY_LS_FORCED) {
        return dst[0] != NULL;
    }

    // In the case of ENCAP we allow fail over, so check to make sure
    // the currently assigned link is OK to continue using
    if(fe->egress.action == POLICY_ACT_ENCAP) {
        //Single interface case
        int max_priority = max_active_interface_priority(interface_list);
        if(dst[0] == NULL || dst[0]->state != ACTIVE || dst[0]->priority < max_priority)
        {
            dst[0] = select_weighted_interface(interface_list);
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