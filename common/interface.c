#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

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

struct interface* find_interface_by_index(struct interface* head, unsigned int index)
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

struct interface* find_interface_by_name(struct interface* head, const char* name)
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

struct interface* find_interface_by_network(struct interface* head, const char* network)
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

/*
 * EMA UPDATE
 *
 * Performs an exponential moving average.  If the old value is NaN, then it is
 * assumed that new_val is the first value in the sequence.
 */
double ema_update(double old_val, double new_val, double new_weight)
{
    if(isnan(old_val)) {
        return new_val;
    } else {
        return ((1.0 - new_weight) * old_val + new_weight * new_val);
    }
}

