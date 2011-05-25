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
 * TODO: May want separate secret words for each controller. */
static int32_t secret_word = 0;

int send_notification()
{
    int sockfd;

    char controller_ip[INET6_ADDRSTRLEN];
    if(get_controller_ip(controller_ip, sizeof(controller_ip)) == FAILURE) {
        DEBUG_MSG("There are no controllers!");
        return FAILURE;
    }

    const unsigned short controller_port =
            get_controller_base_port() + CONTROL_CHANNEL_OFFSET;

    obtain_read_lock(&interface_list_lock);

    struct interface *bind_ife = find_active_interface(interface_list);
    if(!bind_ife) {
        DEBUG_MSG("Cannot send notification, no active interfaces");
        release_read_lock(&interface_list_lock);
        return FAILURE;
    }

    struct timeval timeout;
    timeout.tv_sec  = CCHAN_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    sockfd = tcp_active_open(controller_ip, controller_port, 
            bind_ife->name, &timeout);
    if(sockfd == -1) {
        DEBUG_MSG("Failed to open control channel with controller %s:%d",
                  controller_ip, controller_port);
        release_read_lock(&interface_list_lock);
        return FAILURE;
    }

    struct cchan_notification notification;

    notification.type = CCHAN_NOTIFICATION;
    get_private_ip(&notification.priv_ip);
    notification.unique_id = htons(get_unique_id());

    secret_word = rand();
    notification.secret_word = htonl(secret_word);

    int ife_ind = 0;
    struct interface* ife = interface_list;
    while(ife && ife_ind < MAX_INTERFACES) {
        struct interface_info* dest = &notification.if_info[ife_ind];

        memset(dest, 0, sizeof(*dest));

        strncpy(dest->ifname, ife->name, sizeof(dest->ifname));
        strncpy(dest->network, ife->network, sizeof(dest->network));
        dest->state = ife->state;
        dest->local_ip = ife->public_ip.s_addr;
        dest->data_port = htons(get_base_port());

        ife = ife->next;
        ife_ind++;
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

    close(sockfd);
    return 0;
}

int32_t get_secret_word()
{
    return secret_word;
}

