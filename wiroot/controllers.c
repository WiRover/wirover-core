#include <stdint.h>
#include <stdlib.h>

#include "debug.h"
#include "controllers.h"

static struct node*    controllers_ip_hash = 0;

/*
 * ADD CONTROLLER
 *
 * Adds a controller to list of available controllers.
 */
void add_controller(uint32_t priv_ip, uint32_t pub_ip, double latitude, double longitude)
{
    struct node* node;

    HASH_FIND(hh_ip, controllers_ip_hash, &priv_ip, sizeof(priv_ip), node);
    if(node) {
        // Update an existing node.
        node->pub_ip = pub_ip;
        node->latitude = latitude;
        node->longitude = longitude;
        return;
    }

    node = (struct node*)malloc(sizeof(struct node));
    ASSERT_OR_ELSE(node) {
        DEBUG_MSG("out of memory");
        return;
    }

    node->priv_ip = priv_ip;
    node->pub_ip = pub_ip;
    node->latitude = latitude;
    node->longitude = longitude;

    HASH_ADD(hh_ip, controllers_ip_hash, priv_ip, sizeof(priv_ip), node);
}

/*
 * ASSIGN CONTROLLERS
 *
 * Assigns a gateway to one or more controllers.  node_list must be a valid
 * array of node pointers, which will be filled in by this function.
 * assign_controllers() will return the number of controllers written to the
 * array.
 *
 * TODO: more intelligent assignment, currently we just grab the first
 * list_size controllers
 */
int assign_controllers(struct node** node_list, int list_size, double latitude, double longitude)
{
    ASSERT_OR_ELSE(node_list) {
        DEBUG_MSG("null pointer");
        return 0;
    }

    int nodes = 0;

    struct node* curr_node = controllers_ip_hash;
    while(curr_node && nodes < list_size) {
        node_list[nodes++] = curr_node;

        curr_node = curr_node->hh_ip.next;
    }

    return nodes;
}

