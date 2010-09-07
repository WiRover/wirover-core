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

    char packet[1024];
    struct cchan_notification* notification = (struct cchan_notification*)packet;
    struct cchan_interface_info* ife_info =
           (struct cchan_interface_info*)(packet + sizeof(struct cchan_notification));

    notification->type = CCHAN_NOTIFICATION;
    notification->priv_ip = lease->priv_ip;
    notification->unique_id = lease->unique_id;

    int ife_ind = 0;
    struct interface* ife = obtain_read_lock();
    while(ife) {
        memset(&ife_info[ife_ind], 0, sizeof(ife_info[ife_ind]));

        strncpy(ife_info[ife_ind].ifname, ife->name,
                sizeof(ife_info[ife_ind].ifname));
        strncpy(ife_info[ife_ind].network, ife->network,
                sizeof(ife_info[ife_ind].network));
        ife_info[ife_ind].state = ife->state;

        ife = ife->next;
        ife_ind++;
    }
    release_read_lock();
    
    notification->interfaces = ife_ind;

    close(sockfd);
    return 0;
}

