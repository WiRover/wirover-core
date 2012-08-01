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
#include "kernel.h"

/* The secret word is randomly generated and sent with each notification
 * and ping packet.  The controller uses it to verify the origin of ping
 * packets so that the public IP address can be trusted.
 *
 * TODO: Separate keys for each controller */
uint8_t private_key[SHA256_DIGEST_LENGTH] = { 0 };
uint16_t remote_unique_id = 0;

static uint16_t remote_bw_port = 0;

static int _send_notification(const char *ifname);

int send_notification(int max_tries)
{
    assert(max_tries > 0);

    int i;
    for(i = 0; i < max_tries; i++) {
        obtain_read_lock(&interface_list_lock);

        struct interface_copy *active_list;
        int num_active = copy_active_interfaces(interface_list, &active_list);

        release_read_lock(&interface_list_lock);

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

        free(active_list);
    }

    return -1;
}

/*
 * Makes a single attempt at sending a notification.  The socket is bound
 * to the given interface.
 */
static int _send_notification(const char *ifname)
{
    int sockfd;

    char controller_ip[INET6_ADDRSTRLEN];
    if(get_controller_ip(controller_ip, sizeof(controller_ip)) == FAILURE) {
        DEBUG_MSG("There are no controllers!");
        return FAILURE;
    }

    const unsigned short controller_port = get_controller_control_port();

    struct timeval timeout;
    timeout.tv_sec  = CCHAN_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    sockfd = tcp_active_open(controller_ip, controller_port, 
            ifname, &timeout);
    if(sockfd == -1) {
        DEBUG_MSG("Failed to open control channel with controller %s:%d",
                  controller_ip, controller_port);
        return FAILURE;
    }

    struct cchan_notification notification;

    notification.type = CCHAN_NOTIFICATION;
    get_private_ip(&notification.priv_ip);
    notification.unique_id = htons(get_unique_id());

    memcpy(notification.key, private_key, sizeof(notification.key));

    obtain_read_lock(&interface_list_lock);

    int ife_ind = 0;
    struct interface* ife = interface_list;
    while(ife && ife_ind < MAX_INTERFACES) {
        struct interface_info* dest = &notification.if_info[ife_ind];

        /* Avoid sending interfaces that have not passed the init state. */
        if(ife->state != INIT_INACTIVE) {
            memset(dest, 0, sizeof(*dest));

            strncpy(dest->ifname, ife->name, sizeof(dest->ifname));
            strncpy(dest->network, ife->network, sizeof(dest->network));
            dest->state = ife->state;
            dest->link_id = htonl(ife->index);
            dest->local_ip = ife->public_ip.s_addr;
            dest->data_port = htons(get_data_port());
        
            ife_ind++;
        }

        ife = ife->next;
    }
    
    release_read_lock(&interface_list_lock);

    notification.interfaces = ife_ind;
    
    const size_t notification_len = MIN_NOTIFICATION_LEN +
            ife_ind * sizeof(struct interface_info);

    int bytes = send(sockfd, &notification, notification_len, 0);
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

    bytes = recv_timeout(sockfd, &notification, 
            sizeof(notification), 0, &timeout);
    if(bytes < 0) {
        ERROR_MSG("Receiving notification response failed");
        close(sockfd);
        return -1;
    }

    remote_unique_id = ntohs(notification.unique_id);
    remote_bw_port = ntohs(notification.bw_port);

    close(sockfd);
    return 0;
}

uint16_t get_remote_bw_port()
{
    return remote_bw_port;
}

