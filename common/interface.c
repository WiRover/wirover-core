#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "debug.h"
#include "interface.h"

/*
 * ALLOC INTERFACE
 *
 * Allocate and initialize an interface structure.
 */
struct interface* alloc_interface()
{
    struct interface* ife;

    ife = (struct interface*)malloc(sizeof(struct interface));
    assert(ife);

    memset(ife, 0, sizeof(*ife));
    ife->avg_rtt = NAN;
    ife->avg_downlink_bw = NAN;
    ife->avg_uplink_bw = NAN;

    // Prevent early timeouts
    ife->last_ping_time = time(NULL);
    ife->last_ping_success = time(NULL);

    return ife;
}

/*
 * FREE INTERFACE
 *
 * Frees memory used by the interface structure.  If the interface is contained
 * in any data structures, this will NOT update them.
 */
void free_interface(struct interface* ife)
{
    if(ife) {
        free(ife);
    }
}

struct interface *find_interface_by_index(struct interface *head, unsigned int index)
{
    while(head) {
        if(head->index == index) {
            return head;
        }

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_interface_by_name(struct interface *head, const char *name)
{
    assert(name);

    while(head) {
        if(!strncmp(head->name, name, sizeof(head->name))) {
            return head;
        }
        
        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_interface_by_network(struct interface *head, const char *network)
{
    assert(network);

    while(head) {
        if(!strncmp(head->network, network, sizeof(head->name))) {
            return head;
        }

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_interface_at_pos(struct interface *head, unsigned pos)
{
    unsigned i = 0;

    while(head) {
        if(i == pos)
            return head;

        i++;
        
        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_active_interface(struct interface *head)
{
    while(head) {
        if(head->state == ACTIVE)
            return head;

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

int count_all_interfaces(const struct interface *head)
{
    int count = 0;

    while(head) {
        count++;

        assert(head != head->next);
        head = head->next;
    }

    return count;
}

int count_active_interfaces(const struct interface *head)
{
    int num_active = 0;

    while(head) {
        if(head->state == ACTIVE)
            num_active++;

        assert(head != head->next);
        head = head->next;
    }

    return num_active;
}

/*
 * Creates an array containing information about every interface.  This is
 * useful for performing an action that would otherwise require the interface
 * list to be locked for a long period of time.
 *
 * Returns the number of interfaces or -1 on memory allocation failure.  A
 * return value of > 0 implies that *out points to an array of interface_copy
 * structures.  Remember to free it.
 */
int copy_all_interfaces(const struct interface *head, struct interface_copy **out)
{
    assert(out);

    int n = count_all_interfaces(head);
    if(n == 0)
        return 0;

    unsigned alloc_size = sizeof(struct interface_copy) * n;
    *out = malloc(alloc_size);
    if(!*out) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    memset(*out, 0, alloc_size);
    
    int i = 0;
    while(head && i < n) {
        strncpy((*out)[i].name, head->name, IFNAMSIZ);
        i++;

        head = head->next;
    }
    
    return n;
}

/*
 * Creates an array containing information about every active interface.  This
 * is useful for performing an action that would otherwise require the
 * interface list to be locked for a long period of time.
 *
 * Returns the number of active interfaces or -1 on memory allocation failure.
 * A return value of > 0 implies that *out points to an array of interface_copy
 * structures.  Remember to free it.
 */
int copy_active_interfaces(const struct interface *head, struct interface_copy **out)
{
    assert(out);

    int num_active = count_active_interfaces(head);
    if(num_active == 0)
        return 0;

    unsigned alloc_size = sizeof(struct interface_copy) * num_active;
    *out = malloc(alloc_size);
    if(!*out) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    memset(*out, 0, alloc_size);
    
    int i = 0;
    while(head && i < num_active) {
        if(head->state == ACTIVE) {
            strncpy((*out)[i].name, head->name, IFNAMSIZ);
            i++;
        }

        head = head->next;
    }
    
    return num_active;
}

/*
 * Performs an exponential weighted moving average.  If the old value is NaN, 
 * then it is assumed that new_val is the first value in the sequence.
 */
double ewma_update(double old_val, double new_val, double new_weight)
{
    if(isnan(old_val)) {
        return new_val;
    } else {
        return ((1.0 - new_weight) * old_val + new_weight * new_val);
    }
}

void dump_interfaces(const struct interface *head, const char *prepend)
{
    if(!prepend)
        prepend = "";

    while(head) {
        const char *state;
        switch(head->state) {
            case INIT_INACTIVE:
                state = "INIT";
                break;
            case ACTIVE:
                state = "ACTIVE";
                break;
            case INACTIVE:
                state = "INACTIVE";
                break;
            case DEAD:
                state = "DEAD";
                break;
            default:
                state = "UNKNOWN";
                break;
        }

        DEBUG_MSG("%s%d\t%s\t%s\t%s", 
                prepend, head->index, head->name, head->network, state);

        assert(head != head->next);
        head = head->next;
    }
}

