#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include "contchan.h"
#include "configuration.h"
#include "debug.h"
#include "netlink.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"

/* The secret word is randomly generated and sent with each notification
 * and ping packet.  The controller uses it to verify the origin of ping
 * packets so that the public IP address can be trusted.
 *
 * TODO: Separate keys for each controller */
uint8_t private_key[SHA256_DIGEST_LENGTH] = { 0 };
uint16_t remote_unique_id = 0;

char node_hash[NODE_HASH_SIZE+1];

static uint16_t remote_bw_port = 0;

static int _send_notification(const char *ifname);

//Requries a lock on the interface list
int send_notification(int max_tries)
{
    assert(max_tries > 0);

    int i;
    for(i = 0; i < max_tries; i++) {
        struct interface_copy *active_list = NULL;
        int num_active = copy_active_interfaces(interface_list, &active_list);

        if(num_active <= 0) {
            if(num_active == 0)
                DEBUG_MSG("Cannot send notification, no ACTIVE interfaces");
            return -1;
        }

        int j;
        for(j = 0; j < num_active; j++) {
            int res = _send_notification(active_list[j].name);
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

static void _fill_cchan_notification(struct cchan_notification * notif, uint8_t type) {
    notif->type = type;
    notif->len = sizeof(struct cchan_notification);

    notif->ver_maj = WIROVER_VERSION_MAJOR;
    notif->ver_min = WIROVER_VERSION_MINOR;
    notif->ver_rev = htons(WIROVER_VERSION_REVISION);

    get_private_ip(&notif->priv_ip);
    notif->unique_id = htons(get_unique_id());

    memcpy(notif->key, private_key, sizeof(notif->key));
    memcpy(notif->hash, node_hash, sizeof(notif->hash));
}

/*
 * Makes a single attempt at sending a notification.  The socket is bound
 * to the given interface.
 */
static int _send_notification(const char *ifname)
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

    char *buffer = malloc(BUFSIZ);
    memset(buffer, 0, BUFSIZ);

    int space_left = BUFSIZ;
    int offset = 0;

    struct cchan_notification *notif = (struct cchan_notification *)buffer;
    space_left -= sizeof(struct cchan_notification);
    offset += sizeof(struct cchan_notification);

    _fill_cchan_notification(notif, CCHAN_NOTIFICATION);

    struct interface* ife = interface_list;
    while(ife && space_left > sizeof(struct cchan_notification)) {
        /* Avoid sending interfaces that have not passed the init state. */
        if(ife->state != INIT_INACTIVE) {
            struct interface_info *dest = (struct interface_info *)(buffer + offset);
            space_left -= sizeof(struct interface_info);
            offset += sizeof(struct interface_info);

            dest->type = CCHAN_INTERFACE;
            dest->len = sizeof(struct interface_info);

            dest->link_id = htonl(ife->index);
            strncpy(dest->ifname, ife->name, sizeof(dest->ifname));
            strncpy(dest->network, ife->network, sizeof(dest->network));
            dest->state = ife->state;
            dest->priority = ife->priority;
            dest->local_ip = ife->public_ip.s_addr;
            dest->data_port = htons(get_data_port());
        }

        ife = ife->next;
    }

    const size_t notification_len = offset;

    int bytes = send(sockfd, buffer, notification_len, 0);
    free(buffer);

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

    struct cchan_notification response;

    bytes = recv_timeout(sockfd, &response, 
            sizeof(response), 0, &timeout);
    if(bytes < 0) {
        ERROR_MSG("Receiving notification response failed");
        close(sockfd);
        return -1;
    }

    remote_unique_id = ntohs(response.unique_id);
    remote_bw_port = ntohs(response.bw_port);

    close(sockfd);
    return 0;
}

uint16_t get_remote_bw_port()
{
    return remote_bw_port;
}

int send_shutdown_notification()
{
    int sockfd;
    struct sockaddr_storage cont_dest;
    build_control_sockaddr(get_controller_ife(), &cont_dest);

    struct timeval timeout;
    timeout.tv_sec  = CCHAN_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    sockfd = tcp_active_open(&cont_dest, NULL, &timeout);
    if(sockfd == -1) {
        DEBUG_MSG("Failed to open control channel with controller");
        return FAILURE;
    }

    struct cchan_shutdown notif;
    memset(&notif, 0, sizeof(notif));

    notif.type = CCHAN_SHUTDOWN;
    notif.len = sizeof(notif);

    get_private_ip(&notif.priv_ip);
    notif.unique_id = htons(get_unique_id());
    memcpy(notif.key, private_key, sizeof(notif.key));

    notif.reason = SHUTDOWN_REASON_NORMAL;
    
    int bytes = send(sockfd, &notif, sizeof(notif), 0);

    if(bytes < 0) {
        ERROR_MSG("sending notification failed");
        goto close_and_fail;
    } else if(bytes == 0) {
        DEBUG_MSG("Controller closed control channel");
        goto close_and_fail;
    } else if(bytes < sizeof(notif)) {
        DEBUG_MSG("Full notification packet was not sent, investigate this.");
        goto close_and_fail;
    }

    close(sockfd);
    return 0;

close_and_fail:
    close(sockfd);
    return FAILURE;
}

int send_startup_notification()
{
    FILE *fp = fopen("/etc/wirover.d/node_id","r");
    fgets(node_hash,sizeof(node_hash),fp);
    fclose(fp);

    int sockfd;
    struct sockaddr_storage cont_dest;
    build_control_sockaddr(get_controller_ife(), &cont_dest);

    struct timeval timeout;
    timeout.tv_sec  = CCHAN_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    sockfd = tcp_active_open(&cont_dest, NULL, &timeout);
    if(sockfd == -1) {
        DEBUG_MSG("Failed to open control channel with controller");
        return FAILURE;
    }

    struct cchan_notification notif;
    memset(&notif, 0, sizeof(notif));

    _fill_cchan_notification(&notif, CCHAN_STARTUP);
    
    int bytes = send(sockfd, &notif, sizeof(notif), 0);

    if(bytes < 0) {
        ERROR_MSG("sending notification failed");
        goto close_and_fail;
    } else if(bytes == 0) {
        DEBUG_MSG("Controller closed control channel");
        goto close_and_fail;
    } else if(bytes < sizeof(notif)) {
        DEBUG_MSG("Full notification packet was not sent, investigate this.");
        goto close_and_fail;
    }

    set_nonblock(sockfd, NONBLOCKING);
    timeout.tv_sec = CCHAN_RESPONSE_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    struct cchan_notification response;

    bytes = recv_timeout(sockfd, &response, 
            sizeof(response), 0, &timeout);
    if(bytes < 0) {
        ERROR_MSG("Receiving notification response failed");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return SUCCESS;

close_and_fail:
    close(sockfd);
    return FAILURE;
}