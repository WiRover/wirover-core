#include "interface.h"
#include "select_interface.h"

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

    struct timeval now;
    gettimeofday(&now, NULL);

    while(curr_ife) {
        if(curr_ife->state != ACTIVE || !has_capacity(&curr_ife->rate_control, &now)) {
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

