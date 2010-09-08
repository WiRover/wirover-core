#include <unistd.h>
#include <arpa/inet.h>

#include "contchan.h"
#include "debug.h"
#include "netlink.h"
#include "sockets.h"
#include "common/rootchan.h"

const unsigned short CCHAN_PORT = 8082;

int send_notification(const struct lease_info* lease)
{
    int sockfd;

    if(lease->controllers == 0) {
        DEBUG_MSG("There are no controllers");
        return -1;
    }

    char cont_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &lease->cinfo[0].pub_ip, cont_ip, sizeof(cont_ip));

    sockfd = tcp_active_open(cont_ip, CCHAN_PORT);
    if(sockfd == -1) {
        DEBUG_MSG("Failed to open control channel with controller %s:%d",
                  cont_ip, CCHAN_PORT);
        return -1;
    }

    struct cchan_notification notification;

    notification.type = CCHAN_NOTIFICATION;
    notification.priv_ip = lease->priv_ip;
    notification.unique_id = lease->unique_id;

    int ife_ind = 0;
    struct interface* ife = obtain_read_lock();
    while(ife && ife_ind < MAX_INTERFACES) {
        struct interface_info* dest = &notification.if_info[ife_ind];

        memset(dest, 0, sizeof(*dest));

        strncpy(dest->ifname, ife->name, sizeof(dest->ifname));
        strncpy(dest->network, ife->network, sizeof(dest->network));
        dest->state = ife->state;

        ife = ife->next;
        ife_ind++;
    }
    release_read_lock();
    
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

