#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include "contchan.h"
#include "debug.h"
#include "netlink.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"

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

    sockfd = tcp_active_open(controller_ip, controller_port);
    if(sockfd == -1) {
        DEBUG_MSG("Failed to open control channel with controller %s:%d",
                  controller_ip, controller_port);
        return FAILURE;
    }

    struct cchan_notification notification;

    notification.type = CCHAN_NOTIFICATION;
    notification.priv_ip = get_private_ip();
    notification.unique_id = htons(get_unique_id());

    obtain_read_lock(&interface_list_lock);

    int ife_ind = 0;
    struct interface* ife = interface_list;
    while(ife && ife_ind < MAX_INTERFACES) {
        struct interface_info* dest = &notification.if_info[ife_ind];

        memset(dest, 0, sizeof(*dest));

        strncpy(dest->ifname, ife->name, sizeof(dest->ifname));
        strncpy(dest->network, ife->network, sizeof(dest->network));
        dest->state = ife->state;

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

