#include <ctype.h>
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

