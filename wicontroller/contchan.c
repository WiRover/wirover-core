#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "config.h"
#include "contchan.h"
#include "database.h"
#include "debug.h"
#include "gateway.h"
#include "rootchan.h"
#include "utlist.h"
#include "kernel.h"

static struct gateway* make_gateway(const struct cchan_notification* notif);
static void update_gateway(struct gateway* gw, const struct cchan_notification* notif);
static int send_response(int sockfd, const struct gateway *gw, uint16_t bw_port);

/*
 * TODO: Use OpenSSL for control channel.
 */

/*
 * Parse a notification packet and update the list of gateways accordingly.
 */
int process_notification(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port)
{
    assert(packet);

    // Make sure the packet is at lease large enough for us to read some fields
    // from it.
    if(pkt_len < MIN_NOTIFICATION_LEN) {
        DEBUG_MSG("notification packet was too small to be valid");
        return -1;
    }

    const struct cchan_notification* notif = (const struct cchan_notification*)packet;

    // Make sure the packet is not shorter than the gateway is claiming based
    // on the number of interfaces.  It may be longer than we expect though!
    // We can still accept the packet but not read in more than MAX_INTERFACES.
    const int expected_len = MIN_NOTIFICATION_LEN +
            notif->interfaces * sizeof(struct interface_info);
    if(pkt_len < expected_len) {
        DEBUG_MSG("Received a malformed notification packet");
        return -1;
    }
    
    int state_change = 0;

    struct gateway* gw = lookup_gateway_by_id(ntohs(notif->unique_id));
    if(gw) {
        update_gateway(gw, notif);
    } else {
        gw = make_gateway(notif);
        if(gw)
            add_gateway(gw);

        state_change = 1;
    }

    if(gw) {
        send_response(sockfd, gw, bw_port);

#ifdef WITH_DATABASE
        db_update_gateway(gw, state_change);

        // TODO: We really only need to update links that have changed
        const struct interface *ife;
        DL_FOREACH(gw->head_interface, ife) {
            db_update_link(gw, ife);
        }
#endif

        DEBUG_MSG("Interface list for node %d:", gw->unique_id);
        dump_interfaces(gw->head_interface, "  ");
    }

    return 0;
}

/*
 * Makes a new gateway based on the received notification message.
 */
static struct gateway* make_gateway(const struct cchan_notification* notif)
{
    assert(notif);

    struct gateway* gw = alloc_gateway();

    gw->state = ACTIVE;
    copy_ipaddr(&notif->priv_ip, &gw->private_ip);
    gw->unique_id = ntohs(notif->unique_id);

    memcpy(gw->private_key, notif->key, sizeof(gw->private_key));

    struct in_addr priv_ip;
    ipaddr_to_ipv4(&notif->priv_ip, (uint32_t *)&priv_ip.s_addr);

    virt_add_remote_node(&priv_ip);

    // TODO: This gives the gateway 10.xxx.xxx.0/24 based on its unique_id.
    // This could be made more configurable though.
    uint32_t client_network = htonl(0x0A000000 | (gw->unique_id << 8));
    uint32_t client_netmask = htonl(0xFFFFFF00);
    virt_add_vroute(client_network, client_netmask, priv_ip.s_addr);

    int i;
    for(i = 0; i < notif->interfaces && i < MAX_INTERFACES; i++) {
        struct interface* ife = alloc_interface();

        strncpy(ife->name, notif->if_info[i].ifname, sizeof(ife->name));
        strncpy(ife->network, notif->if_info[i].network, sizeof(ife->network));
        ife->state = notif->if_info[i].state;
        ife->index = ntohl(notif->if_info[i].link_id);
        ife->data_port = notif->if_info[i].data_port;
        ife->public_ip.s_addr = notif->if_info[i].local_ip;

        if(ife->state == ACTIVE) {
            gw->active_interfaces++;

            virt_add_remote_link(&priv_ip, &ife->public_ip, ife->data_port);
        }

        DL_APPEND(gw->head_interface, ife);
    }
    
    char ip_string[INET6_ADDRSTRLEN];
    ipaddr_to_string(&gw->private_ip, ip_string, sizeof(ip_string));

    DEBUG_MSG("Registered new gateway %s (uid %d) with %d active interfaces",
              ip_string, gw->unique_id, gw->active_interfaces);

    return gw;
}

/*
 * Update an exisiting gateway based on the notification message.
 */
static void update_gateway(struct gateway* gw, const struct cchan_notification* notif)
{
    assert(gw && notif);

    gw->state = ACTIVE;

    memcpy(gw->private_key, notif->key, sizeof(gw->private_key));

    struct interface* ife;
    DL_FOREACH(gw->head_interface, ife) {
        ife->state = DEAD;
    }
    gw->active_interfaces = 0;

    struct in_addr priv_ip;
    ipaddr_to_ipv4(&notif->priv_ip, (uint32_t *)&priv_ip.s_addr);

    int i;
    for(i = 0; i < notif->interfaces && i < MAX_INTERFACES; i++) {
        ife = find_interface_by_name(gw->head_interface, notif->if_info[i].ifname);
        if(!ife) {
            ife = alloc_interface();
            
            strncpy(ife->name, notif->if_info[i].ifname, sizeof(ife->name));
            ife->public_ip.s_addr = notif->if_info[i].local_ip;
            ife->data_port = notif->if_info[i].data_port;
            ife->state = DEAD; // will be changed by the following code

            DL_APPEND(gw->head_interface, ife);
        }
        
        strncpy(ife->network, notif->if_info[i].network, sizeof(ife->network));
        ife->index = ntohl(notif->if_info[i].link_id);
        int new_state = notif->if_info[i].state;

        if(ife->state == ACTIVE && new_state != ACTIVE) {
            virt_remove_remote_link(&priv_ip, &ife->public_ip);
        } else if(ife->state != ACTIVE && new_state == ACTIVE) {
            gw->active_interfaces++;

            virt_add_remote_link(&priv_ip, &ife->public_ip, ife->data_port);
        }

        ife->state = new_state;
#ifdef WITH_DATABASE
        db_update_link(gw, ife);
#endif
    }

    struct interface* tmp;
    DL_FOREACH_SAFE(gw->head_interface, ife, tmp) {
        if(ife->state == DEAD) {
            virt_remove_remote_link(&priv_ip, &ife->public_ip);

#ifdef WITH_DATABASE
            db_update_link(gw, ife);
#endif

            DL_DELETE(gw->head_interface, ife);
            free(ife);
        }
    }
    
    char p_ip[INET6_ADDRSTRLEN];
    ipaddr_to_string(&gw->private_ip, p_ip, sizeof(p_ip));

    DEBUG_MSG("Updated gateway %s (uid %d) with %d active interfaces",
              p_ip, gw->unique_id, gw->active_interfaces);
}

static int send_response(int sockfd, const struct gateway *gw, uint16_t bw_port)
{
    struct cchan_notification response;
    memset(&response, 0, sizeof(response));

    response.type = CCHAN_NOTIFICATION;
    get_private_ip(&response.priv_ip);
    response.unique_id = htons(get_unique_id());
    response.bw_port = htons(bw_port);
    response.interfaces = 0;

    memset(response.key, 0, sizeof(response.key));

    int result = send(sockfd, &response, MIN_NOTIFICATION_LEN, 0);
    if(result < 0) {
        ERROR_MSG("Sending notification response failed");
        return -1;
    }

    return 0;
}


