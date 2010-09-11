#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "contchan.h"
#include "debug.h"
#include "gateway.h"
#include "utlist.h"

static struct gateway* make_gateway(const struct cchan_notification* notif);
static void update_gateway(struct gateway* gw, const struct cchan_notification* notif);

/*
 * PROCESS NOTIFICATION
 */
int process_notification(const char* packet, unsigned int pkt_len)
{
    assert(packet);

    if(pkt_len < MIN_NOTIFICATION_LEN) {
        DEBUG_MSG("notification packet was too small to be valid");
        return -1;
    }

    const struct cchan_notification* notif = (const struct cchan_notification*)packet;
    
    //TODO: Check that pkt_len >= the size necessary for the number of
    //interfaces specified by notif->interfaces

    struct gateway* gw = lookup_gateway_by_id(ntohs(notif->unique_id));
    if(gw) {
        update_gateway(gw, notif);

    } else {
        gw = make_gateway(notif);
        
        if(gw) {
            add_gateway(gw);
        }
    }

    return 0;
}

/*
 * MAKE GATEWAY
 *
 * Makes a new gateway based on the received notification message.
 */
static struct gateway* make_gateway(const struct cchan_notification* notif)
{
    assert(notif);

    struct gateway* gw = alloc_gateway();
    gw->private_ip = notif->priv_ip;
    gw->unique_id = ntohs(notif->unique_id);

    int i;
    for(i = 0; i < notif->interfaces && i < MAX_INTERFACES; i++) {
        struct interface* ife = alloc_interface();

        strncpy(ife->name, notif->if_info[i].ifname, sizeof(ife->name));
        strncpy(ife->network, notif->if_info[i].network, sizeof(ife->network));
        ife->state = notif->if_info[i].state;

        if(ife->state == ACTIVE) {
            gw->active_interfaces++;
        }

        DL_APPEND(gw->head_interface, ife);
    }
    
    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &gw->private_ip, p_ip, sizeof(p_ip));

    DEBUG_MSG("Registered new gateway %s (uid %d) with %d active interfaces",
              p_ip, gw->unique_id, gw->active_interfaces);

    return gw;
}

static void update_gateway(struct gateway* gw, const struct cchan_notification* notif)
{
    assert(gw && notif);

    struct interface* ife;
    DL_FOREACH(gw->head_interface, ife) {
        ife->state = DEAD;
    }
    gw->active_interfaces = 0;

    int i;
    for(i = 0; i < notif->interfaces && i < MAX_INTERFACES; i++) {
        int is_new = 0;

        ife = find_interface_by_name(gw->head_interface, notif->if_info[i].ifname);
        if(!ife) {
            is_new = 1;
            ife = alloc_interface();
            strncpy(ife->name, notif->if_info[i].ifname, sizeof(ife->name));
        }
        
        strncpy(ife->network, notif->if_info[i].network, sizeof(ife->network));
        ife->state = notif->if_info[i].state;

        if(is_new) {
            DL_APPEND(gw->head_interface, ife);
        }

        if(ife->state == ACTIVE) {
            gw->active_interfaces++;
        }
    }

    struct interface* tmp;
    DL_FOREACH_SAFE(gw->head_interface, ife, tmp) {
        if(ife->state == DEAD) {
            DL_DELETE(gw->head_interface, ife);
            free(ife);
        }
    }
    
    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &gw->private_ip, p_ip, sizeof(p_ip));

    DEBUG_MSG("Updated gateway %s (uid %d) with %d active interfaces",
              p_ip, gw->unique_id, gw->active_interfaces);
}


