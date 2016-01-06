#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include "contchan.h"
#include "configuration.h"
#include "debug.h"
#include "netlink.h"
#include "packet.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "state.h"

/* The secret word is randomly generated and sent with each notification
 * and ping packet.  The controller uses it to verify the origin of ping
 * packets so that the public IP address can be trusted.
 *
 * TODO: Separate keys for each controller */
uint8_t private_key[SHA256_DIGEST_LENGTH] = { 0 };
uint16_t remote_unique_id = 0;

char node_hash[NODE_HASH_SIZE+1];

static uint16_t remote_bw_port = 0;
static void _add_cchan_notification(struct packet *pkt, uint8_t type);
static void _add_iface_data(struct packet *pkt);
static int _send_notification(int max_tries, struct packet *pkt, int active_only);
static int _send_ife_notification(const char *ifname, struct packet *pkt, struct cchan_notification *response);

int send_notification(int max_tries) {

    struct packet *pkt = alloc_packet(0, BUFSIZ);

    _add_cchan_notification(pkt, CCHAN_NOTIFICATION);
    _add_iface_data(pkt);

    int ret = _send_notification(max_tries, pkt, 1);
    free_packet(pkt);
    //TODO: This should also check that at least one interface has INTERNET connectivity
    if(ret == FAILURE && count_active_interfaces(interface_list) == 0) {
        state &= ~GATEWAY_CONTROLLER_AVAILABLE;
    }
    return ret;
}

//Requries a lock on the interface list
static int _send_notification(int max_tries, struct packet *pkt, int active_only)
{
    assert(max_tries > 0);

    int i;
    for(i = 0; i < max_tries; i++) {
        struct interface_copy *active_list = NULL;
        int num_active;
        if(active_only)
            num_active = copy_active_interfaces(interface_list, &active_list);
        else
            num_active = copy_all_interfaces(interface_list, &active_list);

        if(num_active <= 0) {
            if(num_active == 0)
                DEBUG_MSG("Cannot send notification, no available interfaces");
            return -1;
        }

        int j;
        for(j = 0; j < num_active; j++) {
            struct cchan_notification response;
            int res = _send_ife_notification(active_list[j].name, pkt, &response);

            remote_unique_id = ntohs(response.unique_id);
            remote_bw_port = ntohs(response.bw_port);

            if(res == 0) {
                free(active_list);
                return 0;
            }
        }

        if(active_list) {
            free(active_list);
        }
    }

    return -1;
}

static void _add_cchan_notification(struct packet *pkt, uint8_t type) {
    packet_put(pkt, sizeof(struct cchan_notification));
    struct cchan_notification *notif = (struct cchan_notification *)pkt->data;
    notif->type = type;
    notif->len = sizeof(struct cchan_notification);

    struct wirover_version version = get_wirover_version();
    notif->ver_maj = version.major;
    notif->ver_min = version.minor;
    notif->ver_rev = version.revision;

    get_private_ip(&notif->priv_ip);
    notif->unique_id = htons(get_unique_id());

    memcpy(notif->key, private_key, sizeof(notif->key));
    memcpy(notif->hash, node_hash, sizeof(notif->hash));

    packet_pull(pkt, sizeof(struct cchan_notification));
}

static void _add_iface_data(struct packet *pkt) {
    struct interface* ife = interface_list;
    while(ife && pkt->tail_size > sizeof(struct cchan_notification)) {
        /* Avoid sending interfaces that have not passed the init state. */
        if(ife->state != INIT_INACTIVE) {
            packet_put(pkt, sizeof(struct interface_info));
            struct interface_info *dest = (struct interface_info *)(pkt->data);

            dest->type = CCHAN_INTERFACE;
            dest->len = sizeof(struct interface_info);

            dest->link_id = htonl(ife->index);
            strncpy(dest->ifname, ife->name, sizeof(dest->ifname));
            strncpy(dest->network, ife->network, sizeof(dest->network));
            dest->state = ife->state;
            dest->priority = ife->priority;
            dest->local_ip = ife->public_ip.s_addr;
            dest->data_port = htons(get_data_port());

            packet_pull(pkt, sizeof(struct interface_info));
        }

        ife = ife->next;
    }
}

/*
 * Makes a single attempt at sending a notification.  The socket is bound
 * to the given interface.
 */
static int _send_ife_notification(const char *ifname, struct packet *pkt, struct cchan_notification *response)
{
    int sockfd;
    struct sockaddr_storage cont_dest;
    build_control_sockaddr(get_controller_ife(), &cont_dest);

    struct timeval timeout;
    timeout.tv_sec  = CCHAN_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    sockfd = tcp_active_open(&cont_dest, ifname, &timeout);
    if(sockfd == -1) {
        DEBUG_MSG("Failed to open control channel with controller");
        return FAILURE;
    }
    
    const size_t notification_len = pkt->head_size;

    int bytes = send(sockfd, pkt->buffer, notification_len, 0);

    if(bytes < 0) {
        ERROR_MSG("sending notification failed");
        close(sockfd);
        return -1;
    } else if(bytes == 0) {
        DEBUG_MSG("Controller closed control channel");
        close(sockfd);
        return -1;
    } else if(bytes < notification_len) {
        DEBUG_MSG("Full notification packet was not sent, investigate this.");
        close(sockfd);
        return -1;
    }

    set_nonblock(sockfd, NONBLOCKING);
    timeout.tv_sec = CCHAN_RESPONSE_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    bytes = recv_timeout(sockfd, response, 
            sizeof(struct cchan_notification), 0, &timeout);
    if(bytes <= 0) {
        ERROR_MSG("Receiving notification response failed");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return SUCCESS;
}

uint16_t get_remote_bw_port()
{
    return remote_bw_port;
}

int send_shutdown_notification()
{
    struct packet *pkt = alloc_packet(0, sizeof(struct cchan_shutdown));
    packet_put(pkt, sizeof(struct cchan_shutdown));
    struct cchan_shutdown *notif = (struct cchan_shutdown *)pkt->data;

    notif->type = CCHAN_SHUTDOWN;
    notif->len = sizeof(struct cchan_shutdown);

    get_private_ip(&notif->priv_ip);
    notif->unique_id = htons(get_unique_id());
    memcpy(notif->key, private_key, sizeof(notif->key));

    notif->reason = SHUTDOWN_REASON_NORMAL;
    packet_pull(pkt, sizeof(struct cchan_shutdown));
    
    int ret = _send_notification(1, pkt, 0);

    free_packet(pkt);
    return ret;
}

int send_startup_notification()
{
    FILE *fp = fopen("/etc/wirover.d/node_id","r");
    fgets(node_hash,sizeof(node_hash),fp);
    fclose(fp);

    struct packet *pkt = alloc_packet(0, sizeof(struct cchan_notification));

    _add_cchan_notification(pkt, CCHAN_STARTUP);
    
    int ret = _send_notification(1, pkt, 0);

    free_packet(pkt);
    return ret;
}