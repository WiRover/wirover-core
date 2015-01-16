#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "config.h"
#include "contchan.h"
#include "database.h"
#include "debug.h"
#include "remote_node.h"
#include "rootchan.h"
#include "utlist.h"

static int _process_notification(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port);
static struct remote_node *update_remote_node(const struct cchan_notification *notif);
static void update_interface(struct remote_node *gw, const struct interface_info *ifinfo);
static void remove_dead_interfaces(struct remote_node *gw);
static int send_response(int sockfd, const struct remote_node *gw, uint16_t bw_port);

static int process_shutdown(int sockfd, const char *packet, unsigned int pkt_len);

/*
 * TODO: 
 * - Use OpenSSL for control channel.
 * - There is some funny business with TCP message handling that will probably
 *   work as long as messages and connections are one-to-one but will probably
 *   not work if we allow multiple messages per connection.
 */

/*
 * Parse a notification packet and update the list of remote_nodes accordingly.
 */
int process_notification(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port)
{
    int ret = 0;

    assert(packet);

    /* Make sure the packet is at least large enough to read the type. */
    if(pkt_len < sizeof(struct cchan_header)) {
        DEBUG_MSG("Notification packet was too small to be valid.");
        return -1;
    }

    const struct cchan_header *hdr = (const struct cchan_header*)packet;
    switch(hdr->type) {
            case CCHAN_STARTUP:
            break;
        case CCHAN_NOTIFICATION:
            ret = _process_notification(sockfd, packet, pkt_len, bw_port);
            break;
        case CCHAN_INTERFACE:
            DEBUG_MSG("Received orphaned interface update message");
            break;
        case CCHAN_SHUTDOWN:
            ret = process_shutdown(sockfd, packet, pkt_len);
            break;
        default:
            DEBUG_MSG("Unrecognized control channel message type: %hhu", hdr->type);
            ret = -1;
            break;
    }

    return ret;
}

static int _process_notification(int sockfd, const char *packet, unsigned int pkt_len, uint16_t bw_port)
{
    const struct cchan_notification *notif = (const struct cchan_notification *)packet;
    if(pkt_len < MIN_NOTIFICATION_LEN || notif->len < MIN_NOTIFICATION_LEN) {
        DEBUG_MSG("Notification packet is too small (size %u)", pkt_len);
        return -1;
    }
    
    int gw_state_change = 0;

    struct remote_node *gw = update_remote_node(notif);
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
            case CCHAN_NOTIFICATION:
                DEBUG_MSG("Expected interface update but received another notification");
                break;
            case CCHAN_INTERFACE:
                {
                    if(hdr->len < MIN_INTERFACE_INFO_LEN) {
                        DEBUG_MSG("Interface info structure too small (size %hhu)", hdr->len);
                        break;
                    }

                    const struct interface_info *ifinfo = 
                        (const struct interface_info *)(packet + offset);
                    update_interface(gw, ifinfo);
                    break;
                }
            default:
                break;
        }

        offset += hdr->len;
    }

    remove_dead_interfaces(gw);

    send_response(sockfd, gw, bw_port);

#ifdef WITH_DATABASE
    db_update_gateway(gw, gw_state_change);
#endif

    return 0;
}

/*
 * Update a remote_node based on the received notification message.
 */
static struct remote_node *update_remote_node(const struct cchan_notification *notif)
{
    assert(notif);

    struct remote_node *gw = lookup_remote_node_by_id(ntohs(notif->unique_id));
    if(!gw) {
        gw = alloc_remote_node();
        if(!gw)
            return NULL;

        copy_ipaddr(&notif->priv_ip, &gw->private_ip);
        gw->unique_id = ntohs(notif->unique_id);
        memcpy(gw->hash, notif->hash, NODE_HASH_SIZE);

        add_remote_node(gw);
    }

    // Don't update a remote node if it's sent a hash you didn't expect!
    char notif_hash[NODE_HASH_SIZE + 1];
    notif_hash[NODE_HASH_SIZE -1] = 0;
    memcpy(notif_hash, notif->hash, NODE_HASH_SIZE);

    if(strcmp(gw->hash, notif_hash))
    {
        DEBUG_MSG("A uniqueid collision has occured between %s and %s", gw->hash, notif_hash);
        return NULL;
    }

    memcpy(gw->private_key, notif->key, sizeof(gw->private_key));
    /*gw->hash is size NODE_HASH_SIZE + 1 and is initialized to 0
      this null terminates the string*/
    
    int state_change = 0;

    if(gw->state != ACTIVE) {
        gw->state = ACTIVE;
        state_change = 1;

  

        char p_ip[INET6_ADDRSTRLEN];
        ipaddr_to_string(&gw->private_ip, p_ip, sizeof(p_ip));

        DEBUG_MSG("Registered remote_node %s (uid %d) version %hhu.%hhu.%hu", 
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
static void update_interface(struct remote_node *gw, const struct interface_info *ifinfo)
{
    struct interface *ife;

    ife = find_interface_by_name(gw->head_interface, ifinfo->ifname);
    if(!ife) {
        ife = alloc_interface(gw->unique_id);
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
    if(ife->state != ACTIVE && new_state == ACTIVE) {
        gw->active_interfaces++;
    }
    change_interface_state(ife, new_state);

    if(ifinfo->priority != ife->priority) {
        ife->priority = ifinfo->priority;
    }

    ife->update_num = gw->cchan_updates;

#ifdef WITH_DATABASE
    db_update_link(gw, ife);
#endif
}

/*
 * Remove interfaces that have been marked DEAD or were not included in the
 * recent notification, meaning the remote_node no longer uses them.
 */
static void remove_dead_interfaces(struct remote_node *gw)
{
    struct interface *ife;
    struct interface *ife_tmp;
    
    struct in_addr priv_ip;
    ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&priv_ip.s_addr);

    DL_FOREACH_SAFE(gw->head_interface, ife, ife_tmp) {
        if(ife->state == DEAD || ife->update_num != gw->cchan_updates) {
            if(ife->state == ACTIVE)
                gw->active_interfaces--;

#ifdef WITH_DATABASE
            db_update_link(gw, ife);
#endif

            DL_DELETE(gw->head_interface, ife);
            free(ife);
        }
    }
}

static int send_response(int sockfd, const struct remote_node *gw, uint16_t bw_port)
{
    struct cchan_notification response;
    memset(&response, 0, sizeof(response));

    response.type = CCHAN_NOTIFICATION;
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

    struct remote_node *gw = lookup_remote_node_by_id(ntohs(notif->unique_id));
    if(!gw) {
        DEBUG_MSG("Received shutdown notification for unrecognized remote_node %hhu", notif->unique_id);
        return -1;
    }

    if(memcmp(gw->private_key, notif->key, sizeof(gw->private_key)) != 0) {
        DEBUG_MSG("Received shutdown notification with non-matching key for remote_node %hhu", notif->unique_id);
        return -1;
    }

    DEBUG_MSG("Received shutdown for remote_node %hhu", gw->unique_id);
    remove_remote_node(gw);

    return 0;
}

