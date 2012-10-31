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

static int process_notification_v2(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port);
static struct gateway *update_gateway_v2(const struct cchan_notification_v2 *notif);
static void update_interface_v2(struct gateway *gw, const struct interface_info_v2 *ifinfo);
static void remove_dead_interfaces(struct gateway *gw);
static int send_response_v2(int sockfd, const struct gateway *gw, uint16_t bw_port);

static int process_shutdown(int sockfd, const char *packet, unsigned int pkt_len);
static int remove_gateway(struct gateway *gw);

static int process_notification_v1(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port);
static struct gateway* make_gateway_v1(const struct cchan_notification_v1* notif);
static void update_gateway_v1(struct gateway* gw, const struct cchan_notification_v1* notif);
static int send_response_v1(int sockfd, const struct gateway *gw, uint16_t bw_port);

/*
 * TODO: 
 * - Use OpenSSL for control channel.
 * - There is some funny business with TCP message handling that will probably
 *   work as long as messages and connections are one-to-one but will probably
 *   not work if we allow multiple messages per connection.
 */

/*
 * Parse a notification packet and update the list of gateways accordingly.
 */
int process_notification(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port)
{
    assert(packet);

    /* Make sure the packet is at least large enough to read the type. */
    if(pkt_len < sizeof(struct cchan_header)) {
        DEBUG_MSG("Notification packet was too small to be valid.");
        return -1;
    }

    const struct cchan_header *hdr = (const struct cchan_header*)packet;
    switch(hdr->type) {
        case CCHAN_NOTIFICATION_V1:
            return process_notification_v1(sockfd, packet, pkt_len, bw_port);
        case CCHAN_NOTIFICATION_V2:
            return process_notification_v2(sockfd, packet, pkt_len, bw_port);
        case CCHAN_INTERFACE:
            DEBUG_MSG("Received orphaned interface update message");
            break;
        case CCHAN_SHUTDOWN:
            return process_shutdown(sockfd, packet, pkt_len);
        default:
            DEBUG_MSG("Unrecognized control channel message type: %hhu", hdr->type);
            return -1;
    }

    return 0;
}

static int process_notification_v2(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port)
{
    const struct cchan_notification_v2 *notif = (const struct cchan_notification_v2 *)packet;
    if(pkt_len < MIN_NOTIFICATION_V2_LEN || notif->len < MIN_NOTIFICATION_V2_LEN) {
        DEBUG_MSG("Notification packet is too small (size %u)", pkt_len);
        return -1;
    }
    
    int gw_state_change = 0;

    struct gateway *gw = update_gateway_v2(notif);
    if(!gw)
        return -1;

    /* Number of control channel updates is used to check which interfaces have
     * not been updated recently. */
    gw->cchan_updates++;
    
    unsigned offset = notif->len;
    while(offset < pkt_len) {
        const struct cchan_header *hdr = (const struct cchan_header *)(packet + offset);
        if(offset + hdr->len > pkt_len)
            break;

        switch(hdr->type) {
            case CCHAN_NOTIFICATION_V1:
            case CCHAN_NOTIFICATION_V2:
                DEBUG_MSG("Expected interface update but received another notification");
                break;
            case CCHAN_INTERFACE:
                {
                    if(hdr->len < MIN_INTERFACE_INFO_V2_LEN) {
                        DEBUG_MSG("Interface info structure too small (size %hhu)", hdr->len);
                        break;
                    }

                    const struct interface_info_v2 *ifinfo = 
                        (const struct interface_info_v2 *)(packet + offset);
                    update_interface_v2(gw, ifinfo);
                    break;
                }
            default:
                break;
        }

        offset += hdr->len;
    }

    remove_dead_interfaces(gw);

    send_response_v2(sockfd, gw, bw_port);

#ifdef WITH_DATABASE
    db_update_gateway(gw, gw_state_change);
#endif

    DEBUG_MSG("Interface list for node %d:", gw->unique_id);
    dump_interfaces(gw->head_interface, "  ");

    return 0;
}

/*
 * Update a gateway based on the received notification message.
 */
static struct gateway *update_gateway_v2(const struct cchan_notification_v2 *notif)
{
    assert(notif);

    struct gateway *gw = lookup_gateway_by_id(ntohs(notif->unique_id));
    if(!gw) {
        gw = alloc_gateway();
        if(!gw)
            return NULL;

        copy_ipaddr(&notif->priv_ip, &gw->private_ip);
        gw->unique_id = ntohs(notif->unique_id);

        add_gateway(gw);
    }
    
    memcpy(gw->private_key, notif->key, sizeof(gw->private_key));
    
    int state_change = 0;

    if(gw->state != ACTIVE) {
        gw->state = ACTIVE;
        state_change = 1;

        struct in_addr priv_ip;
        ipaddr_to_ipv4(&notif->priv_ip, (uint32_t *)&priv_ip.s_addr);

        virt_add_remote_node(&priv_ip);

        // TODO: This gives the gateway 10.xxx.xxx.0/24 based on its unique_id.
        // This could be made more configurable though.
        uint32_t client_network = htonl(0x0A000000 | (gw->unique_id << 8));
        uint32_t client_netmask = htonl(0xFFFFFF00);
        virt_add_vroute(client_network, client_netmask, priv_ip.s_addr);

        char p_ip[INET6_ADDRSTRLEN];
        ipaddr_to_string(&gw->private_ip, p_ip, sizeof(p_ip));

        DEBUG_MSG("Registered gateway %s (uid %d) version %hhu.%hhu.%hu", 
                p_ip, gw->unique_id, notif->ver_maj, notif->ver_min, ntohs(notif->ver_rev));
    }

#ifdef WITH_DATABASE
    db_update_gateway(gw, state_change);
#endif

    return gw;
}

/*
 * Update an interface from the notification.
 */
static void update_interface_v2(struct gateway *gw, const struct interface_info_v2 *ifinfo)
{
    struct interface *ife;

    ife = find_interface_by_name(gw->head_interface, ifinfo->ifname);
    if(!ife) {
        ife = alloc_interface();
        if(!ife)
            return;

        strncpy(ife->name, ifinfo->ifname, sizeof(ife->name));
        ife->public_ip.s_addr = ifinfo->local_ip;
        ife->data_port = ifinfo->data_port;

        /* These will be changed by the following code. */
        ife->state = DEAD;
        ife->priority = 0;

        DL_APPEND(gw->head_interface, ife);
    }
 
    strncpy(ife->network, ifinfo->network, sizeof(ife->network));
    ife->index = ntohl(ifinfo->link_id);
    
    struct in_addr priv_ip;
    ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&priv_ip.s_addr);

    int new_state = ifinfo->state;
    if(ife->state == ACTIVE && new_state != ACTIVE) {
        virt_remove_remote_link(&priv_ip, &ife->public_ip);
    } else if(ife->state != ACTIVE && new_state == ACTIVE) {
        gw->active_interfaces++;

        virt_add_remote_link(&priv_ip, &ife->public_ip, ife->data_port);
    }
    ife->state = new_state;

    if(ifinfo->priority != ife->priority) {
        ife->priority = ifinfo->priority;
        virt_remote_prio(&priv_ip, &ife->public_ip, ife->priority);
    }

    ife->update_num = gw->cchan_updates;

#ifdef WITH_DATABASE
    db_update_link(gw, ife);
#endif
}

/*
 * Remove interfaces that have been marked DEAD or were not included in the
 * recent notification, meaning the gateway no longer uses them.
 */
static void remove_dead_interfaces(struct gateway *gw)
{
    struct interface *ife;
    struct interface *ife_tmp;
    
    struct in_addr priv_ip;
    ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&priv_ip.s_addr);

    DL_FOREACH_SAFE(gw->head_interface, ife, ife_tmp) {
        if(ife->state == DEAD || ife->update_num != gw->cchan_updates) {
            if(ife->state == ACTIVE)
                gw->active_interfaces--;

            virt_remove_remote_link(&priv_ip, &ife->public_ip);

#ifdef WITH_DATABASE
            db_update_link(gw, ife);
#endif

            DL_DELETE(gw->head_interface, ife);
            free(ife);
        }
    }
}

static int send_response_v2(int sockfd, const struct gateway *gw, uint16_t bw_port)
{
    struct cchan_notification_v2 response;
    memset(&response, 0, sizeof(response));

    response.type = CCHAN_NOTIFICATION_V2;
    response.len = sizeof(response);

    response.ver_maj = WIROVER_VERSION_MAJOR;
    response.ver_min = WIROVER_VERSION_MINOR;
    response.ver_rev = htons(WIROVER_VERSION_REVISION);

    get_private_ip(&response.priv_ip);
    response.unique_id = htons(get_unique_id());
    memset(response.key, 0, sizeof(response.key));
    response.bw_port = htons(bw_port);

    int result = send(sockfd, &response, sizeof(response), 0);
    if(result < 0) {
        ERROR_MSG("Sending notification response failed");
        return -1;
    }

    return 0;
}

static int process_shutdown(int sockfd, const char *packet, unsigned int pkt_len)
{
    const struct cchan_shutdown *notif = (const struct cchan_shutdown *)packet;
    if(pkt_len < sizeof(struct cchan_shutdown) || notif->len < sizeof(struct cchan_shutdown)) {
        DEBUG_MSG("Notification packet is too small (size %u)", pkt_len);
        return -1;
    }

    struct gateway *gw = lookup_gateway_by_id(ntohs(notif->unique_id));
    if(!gw) {
        DEBUG_MSG("Received shutdown notification for unrecognized gateway %hhu", notif->unique_id);
        return -1;
    }

    if(memcmp(gw->private_key, notif->key, sizeof(gw->private_key)) != 0) {
        DEBUG_MSG("Received shutdown notification with non-matching key for gateway %hhu", notif->unique_id);
        return -1;
    }

    remove_gateway(gw);

    return 0;
}

/*
 * This updates the gateway state in the database and frees all of the
 * structures associated with the gateway and its interfaces.
 *
 * As a result of this function call, the memory pointed to by gw will be
 * freed.
 */
static int remove_gateway(struct gateway *gw)
{
    struct interface *ife;
    struct interface *tmp_ife;

    struct in_addr private_ip;
    ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&private_ip.s_addr);

    DL_FOREACH_SAFE(gw->head_interface, ife, tmp_ife) {
        if(ife->state != DEAD) {
            ife->state = DEAD;

#ifdef WITH_DATABASE
            db_update_link(gw, ife);
#endif

            if(ife->state == ACTIVE) {
                gw->active_interfaces--;
                virt_remove_remote_link(&private_ip, &ife->public_ip);
            }
        }

        DL_DELETE(gw->head_interface, ife);
        free(ife);
    }

    virt_remove_remote_node(&private_ip);

    // TODO: This could be made more configurable.
    uint32_t client_network = htonl(0x0A000000 | ((uint32_t)gw->unique_id << 8));
    uint32_t client_netmask = htonl(0xFFFFFF00);
    virt_delete_vroute(client_network, client_netmask, private_ip.s_addr);
                
    gw->state = DEAD;

#ifdef WITH_DATABASE
    db_update_gateway(gw, 1);
#endif

    HASH_DELETE(hh_id, gateway_id_hash, gw);
    free(gw);

    return 0;
}


static int process_notification_v1(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port)
{
    if(pkt_len < MIN_NOTIFICATION_LEN) {
        DEBUG_MSG("Notification packet is too small (size %u)", pkt_len);
        return -1;
    }

    const struct cchan_notification_v1* notif = (const struct cchan_notification_v1*)packet;

    // Make sure the packet is not shorter than the gateway is claiming based
    // on the number of interfaces.  It may be longer than we expect though!
    // We can still accept the packet but not read in more than MAX_INTERFACES.
    const int expected_len = MIN_NOTIFICATION_LEN +
            notif->interfaces * sizeof(struct interface_info_v1);
    if(pkt_len < expected_len) {
        DEBUG_MSG("Received a malformed notification packet");
        return -1;
    }
    
    int state_change = 0;

    struct gateway* gw = lookup_gateway_by_id(ntohs(notif->unique_id));
    if(gw) {
        update_gateway_v1(gw, notif);
    } else {
        gw = make_gateway_v1(notif);
        if(gw)
            add_gateway(gw);

        state_change = 1;
    }

    if(gw) {
        send_response_v1(sockfd, gw, bw_port);

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
static struct gateway* make_gateway_v1(const struct cchan_notification_v1* notif)
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
static void update_gateway_v1(struct gateway* gw, const struct cchan_notification_v1* notif)
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

static int send_response_v1(int sockfd, const struct gateway *gw, uint16_t bw_port)
{
    struct cchan_notification_v1 response;
    memset(&response, 0, sizeof(response));

    response.type = CCHAN_NOTIFICATION_V1;
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


