#include "interface.h"
#include "select_interface.h"
#include "debug.h"

struct interface *select_mp_interface(struct interface *head)
{
    struct interface *select_ife = NULL;

    int size = count_active_interfaces(head);
    if (size <= 0)
        return NULL;
    
    struct interface *interfaces[size];
    struct interface *curr_ife = head;
    int highest_priority = 0;
    int ife_count = 0;

    while(curr_ife) {
        if(curr_ife->state != ACTIVE || !has_capacity(&curr_ife->rate_control)) {
            curr_ife = curr_ife->next;
            continue;
        }

        if(curr_ife->priority > highest_priority) {
            highest_priority = curr_ife->priority;
            ife_count = 0;
        }

        if(curr_ife->priority == highest_priority) {
            interfaces[ife_count] = curr_ife;
            ife_count++;
        }

        curr_ife = curr_ife->next;
    }

    if (ife_count <= 0)
        return NULL;

    double min_rtt = interfaces[0]->avg_rtt;
    select_ife = interfaces[0];

    for (int i = 1; i < ife_count; i++) {
        if (interfaces[i]->avg_rtt < min_rtt) {
            min_rtt = interfaces[i]->avg_rtt;
            select_ife = interfaces[i];
        }
    }

    return select_ife;
}

struct interface *select_wrr_interface(struct interface *head)
{
    //Find the subset of interfaces with the highest priority
    int size = count_active_interfaces(head);
    if(size == 0) { return NULL; }
    struct interface *interfaces[size];
    struct interface *curr_ife = head;
    int highest_priority = 0;
    int ife_count = 0;
    //TODO: This is total shit
    while(curr_ife) {
        if(curr_ife->state != ACTIVE || !has_capacity(&curr_ife->rate_control)) {
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
    if(ife_count == 0) { return NULL; }
    double sum_weights = 0;
    double weights[ife_count];
    double weight;
    for(int i = 0; i < ife_count; i++){
        weight = calc_bw_down(interfaces[i]);
        weights[i] = weight;
        sum_weights += weight;
    }
    double choice = rand() / (double)RAND_MAX * sum_weights;
    int i = 0;
    for(; i < ife_count; i++){
        choice -= weights[i];
        if(choice <= 0) { break; }
    }
    if(i >= ife_count){
        DEBUG_MSG("Link selection algorithm failure!");
        return NULL;
    }
    return interfaces[i];
}

int select_all_interfaces(struct interface *head, struct interface ** dst, int size)
{
    int i = 0;
    while(head && i < size)
    {
        dst[i] = head;
        i++;
        head = head->next;
    }
    return i;
}