#include <arpa/inet.h>
#include <math.h>
#include "interface.h"
#include "debug.h"
#include "sockets.h"
#include "remote_node.h"
#include "tunnel.h"
#include "select_interface.h"
#include "rootchan.h"


struct interface *select_src_interface(struct flow_entry *fe)
{
    struct interface *output = find_interface_by_index(interface_list, fe->local_link_id);
    if(output == NULL || output->state != ACTIVE || output->st_state == ST_STALLED)
    {
        //Find the subset of interfaces with the highest priority
        int size = count_active_interfaces(interface_list);
        if(size == 0) { return NULL; }
        struct interface *interfaces[size];
        struct interface *curr_ife = interface_list;
        int highest_priority = 0;
        int ife_count = 0;
        while(curr_ife) {
            if(curr_ife->state != ACTIVE || curr_ife->st_state == ST_STALLED) { 
                curr_ife = curr_ife->next;
                continue;
            }
            if(curr_ife->priority > highest_priority){
                highest_priority = curr_ife->priority;
                ife_count = 0;
            }

            if(curr_ife->priority == highest_priority){
                interfaces[ife_count] = curr_ife;
                ife_count++;
            }
            curr_ife = curr_ife->next;
        }
        long sum_weights = 0;
        long weights[ife_count];
        long weight;
        for(int i = 0; i < ife_count; i++){
            weight = calc_bw_hint(interfaces[i]);
            weights[i] = weight;
            sum_weights += weight;
        }
        long choice = round(rand() / (double)RAND_MAX * sum_weights);
        int i = 0;
        for(; i < ife_count; i++){
            choice -= weights[i];
            if(choice <= 0) { break; }
        }
        output = interfaces[i];
    }
    update_flow_entry(fe);
    return output;
}
struct interface *select_dst_interface(struct flow_entry *fe)
{
    struct remote_node *controller = lookup_remote_node_by_id(get_lease_info()->cinfo[0].unique_id);
    if(controller == NULL){
        return NULL;
    }
    return controller->head_interface;
}