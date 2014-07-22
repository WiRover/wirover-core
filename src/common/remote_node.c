#include <stdlib.h>

#include "config.h"
#include "debug.h"
#include "remote_node.h"
#include "netlink.h"

struct remote_node* remote_node_id_hash = 0;

/*
 * ALLOC remote_node
 */
struct remote_node* alloc_remote_node()
{
    struct remote_node* node = (struct remote_node*)malloc(sizeof(struct remote_node));
    assert(node);
    memset(node, 0, sizeof(struct remote_node));
    
    node->creation_time = time(0);
    node->last_ping_time = node->creation_time;
    node->active_interfaces = 0;
    node->head_interface = 0;

    return node;
}

/*
 * ADD remote_node
 */
void add_remote_node(struct remote_node* node)
{
    ASSERT_OR_ELSE(node) {
        return;
    }
    HASH_ADD(hh_id, remote_node_id_hash, unique_id, sizeof(node->unique_id), node);
}

/*
 * LOOKUP remote_node BY ID
 */
struct remote_node* lookup_remote_node_by_id(unsigned short id)
{
    struct remote_node* node;
    HASH_FIND(hh_id, remote_node_id_hash, &id, sizeof(id), node);
    return node;
}

