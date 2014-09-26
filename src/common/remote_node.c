#include <stdlib.h>
#include <arpa/inet.h>

#include "config.h"
#include "debug.h"
#include "remote_node.h"
#include "netlink.h"
#include "packet_buffer.h"
#include "utlist.h"
#ifdef CONTROLLER
#include "database.h"
#endif

struct remote_node* remote_node_id_hash = 0;
struct rwlock remote_node_lock = RWLOCK_INITIALIZER;
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
    node->rec_seq_buffer = pb_alloc_seq_buffer();

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
    obtain_write_lock(&remote_node_lock);
    HASH_ADD(hh_id, remote_node_id_hash, unique_id, sizeof(node->unique_id), node);
    release_write_lock(&remote_node_lock);
}

/*
 * LOOKUP remote_node BY ID
 */
struct remote_node* lookup_remote_node_by_id(unsigned short id)
{
    struct remote_node* node;
    obtain_read_lock(&remote_node_lock);
    HASH_FIND(hh_id, remote_node_id_hash, &id, sizeof(id), node);
    release_read_lock(&remote_node_lock);
    return node;
}


//Assumes the calling function has a lock on remote_node_lock
int remove_remote_node(struct remote_node *gw)
{
    struct interface *ife;
    struct interface *tmp_ife;

    struct in_addr private_ip;
    ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&private_ip.s_addr);

    DL_FOREACH_SAFE(gw->head_interface, ife, tmp_ife) {
        if(ife->state != INACTIVE) {
            ife->state = INACTIVE;

#if defined(CONTROLLER) && defined(WITH_DATABASE)
            db_update_link(gw, ife);
#endif

            if(ife->state == ACTIVE) {
                gw->active_interfaces--;
            }
        }

        DL_DELETE(gw->head_interface, ife);
        free(ife);
    }
                
    gw->state = INACTIVE;
    
#if defined(CONTROLLER) && defined(WITH_DATABASE)
    db_update_gateway(gw, 1);
#endif

    HASH_DELETE(hh_id, remote_node_id_hash, gw);
    free(gw);

    return 0;
}

