#include <stdlib.h>

#include "debug.h"
#include "gateway.h"
#include "netlink.h"

static struct gateway* gateway_id_hash = 0;

/*
 * ALLOC GATEWAY
 */
struct gateway* alloc_gateway()
{
    struct gateway* gw = (struct gateway*)malloc(sizeof(struct gateway));
    assert(gw);
    
    gw->creation_time = time(0);
    gw->active_interfaces = 0;
    gw->head_interface = 0;

    return gw;
}

/*
 * ADD GATEWAY
 */
void add_gateway(struct gateway* gw)
{
    ASSERT_OR_ELSE(gw) {
        return;
    }
    HASH_ADD(hh_id, gateway_id_hash, unique_id, sizeof(gw->unique_id), gw);
}

/*
 * LOOKUP GATEWAY BY ID
 */
struct gateway* lookup_gateway_by_id(unsigned short id)
{
    struct gateway* gw;
    HASH_FIND(hh_id, gateway_id_hash, &id, sizeof(id), gw);
    return gw;
}

