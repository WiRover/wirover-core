/* vim: set et ts=4 sw=4: */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "gatewayUpdater.h"
#include "../common/contChan.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/special.h"
#include "../common/udp_ping.h"
#include "../common/utils.h"

// Internal functions
void*   pingServerThread(void* serverInfo);
int     createPingSocket(unsigned short local_port);
int     handleInboundPing(int sockfd, char* buffer, int numBytes,
                          struct sockaddr* from, socklen_t fromSize);

/*
 * I N I T   P I N G   T H R E A D
 *
 * Starts a thread for sending and receiving UDP pings.
 *
 * Returns SUCCESS or FAILURE.
 */
int startPingServerThread(struct ping_server_info* serverInfo)
{
    serverInfo->sockfd = createPingSocket(serverInfo->local_port);
    if(serverInfo->sockfd == -1) {
        return FAILURE;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int rtn = setsockopt(serverInfo->sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if(rtn < 0) {
        ERROR_MSG("setsockopt SO_RCVTIMEO failed");
        return FAILURE;
    }

    if(pthread_create(&serverInfo->thread, 0, pingServerThread, serverInfo) != 0) {
        DEBUG_MSG("pthread_create failed");
        return FAILURE;
    }

    return SUCCESS;
} /* end function initPingThread */

/*
 * C R E A T E   P I N G   S O C K E T
 *
 * Creates a socket for sending and receiving UDP pings.  If localPort is 0, it
 * binds to an arbitrary free port.  Returns -1 on failure or the socket file
 * descriptor.
 */
int createPingSocket(unsigned short localPort)
{
    int sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return -1;
    }

    // Allow multiple sockets to bind to the port
    const int yes = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        DEBUG_MSG("SO_REUSEADDR failed");
        close(sockfd);
        return FAILURE;
    }

    struct sockaddr_in bindAddr;
    memset(&bindAddr, 0, sizeof(struct sockaddr_in));
    bindAddr.sin_family         = AF_INET;
    bindAddr.sin_port           = htons(localPort);
    bindAddr.sin_addr.s_addr    = htonl(INADDR_ANY);

    if(bind(sockfd, (struct sockaddr*)&bindAddr, sizeof(struct sockaddr_in)) < 0) {
        ERROR_MSG("binding socket failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
} /* end function createPingSocket */

void* pingServerThread(void* serverInfo)
{
    struct ping_server_info* info = (struct ping_server_info*)serverInfo;

    char buffer[MTU];
    struct sockaddr_in from;

    while(!getQuitFlag()) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(info->sockfd, &readSet);

        int rtn = select(info->sockfd+1, &readSet, 0, 0, 0);
        //DEBUG_MSG("ping select:%d",rtn);
        if(rtn < 0) {
            if(errno == EINTR) {
                DEBUG_MSG("Warning: select was interrupted");
                continue;
            } else {
                ERROR_MSG("select failed");
                continue;
            }
        }

        socklen_t fromSize = sizeof(struct sockaddr_in);
        int bytes = recvfrom(info->sockfd, buffer, MTU, 0,
                (struct sockaddr*)&from, &fromSize);
        if(bytes >= sizeof(struct tunhdr) + 2) {
            // The bounds check assures us it's safe to read in the tunnel header
            // and the next two bytes which specify the special packet type.
            handleInboundPing(info->sockfd, buffer, bytes, (struct sockaddr*)&from, fromSize);
        }
    }

    return 0;
}

int handleInboundPing(int sockfd, char* buffer, int numBytes, struct sockaddr* from, socklen_t fromSize)
{
    struct tunhdr* tun_hdr = (struct tunhdr*)buffer;
    unsigned short h_node_id = ntohs(tun_hdr->node_id);
    unsigned short h_link_id = ntohs(tun_hdr->link_id);
    unsigned short h_type = ntohs(*(uint16_t*)(buffer + sizeof(struct tunhdr)));

    if(h_type == SPKT_UDP_PING) {
        struct ping_pkt *ping_h = (struct ping_pkt*)(buffer + sizeof(struct tunhdr));

        gettimeofday(&ping_h->rcvd_time, NULL);

        if(sendto(sockfd, buffer, numBytes, 0, from, fromSize) < 0) {
            DEBUG_MSG("sendto() failed");
        }

        if(numBytes >= sizeof(struct tunhdr) + sizeof(struct ping_pkt)) {
            //struct tunhdr* tun_hdr = (struct tunhdr*)buffer;
            struct ping_pkt* pkt = (struct ping_pkt*)(buffer + sizeof(struct tunhdr));

            STATS_MSG("Ping from node %d, link %d, bytes:%d", h_node_id, h_link_id, numBytes);
            /*STATS_MSG("GPS from node %d link %d: %d,%f,%f,%f,%f,%f,%f",
                    h_node_id, h_link_id, 
                    pkt->gps.status, pkt->gps.latitude, pkt->gps.longitude,
                    pkt->gps.altitude, pkt->gps.track, pkt->gps.speed, pkt->gps.climb);
            */

            struct wigateway* gw = searchWigatewaysByNodeID(h_node_id);
            if(gw) {
                time(&gw->last_seen_pkt_time);

                gw->gps_status = pkt->gps.status;
                gw->latitude = pkt->gps.latitude;
                gw->longitude = pkt->gps.longitude;
                gw->altitude = pkt->gps.altitude;

                // Use the ping source address to set the link's IP address,
                // since this is the first packet that a gateway must send
                // before it is able to use a new link.
                // TODO: This is not really secure or ideal.  We need to put
                // more thought into how we discover the gateway's public IP.
                struct link *link = searchLinksById(gw->head_link, h_link_id);
                if(link) {
                    time(&link->last_packet_received);
                    setLinkIp(link, from, fromSize);
                }

#ifdef WITH_MYSQL                
                if(h_node_id != 0 && pkt->gps.status > 1) {
                    gw_update_gps(gw, &pkt->gps);
                }
#endif
            }
        }
    } else if(h_type == SPKT_PING_STATS) {
        struct ping_stats_pkt* pkt = (struct ping_stats_pkt*)(buffer + sizeof(struct tunhdr));
        int h_rtt = ntohl(pkt->rtt);

        STATS_MSG("Ping from node %d link %d rtt: %d usec",
                h_node_id, h_link_id, h_rtt);
            
        struct wigateway* gw = searchWigatewaysByNodeID(h_node_id);
        if(gw) {
            time(&gw->last_seen_pkt_time);

            struct link* link = searchLinksById(gw->head_link, h_link_id);
            if(link) {
                time(&link->last_packet_received);

                //TODO: decide how to do the averaging
                link->avg_rtt = 0.5 * link->avg_rtt +
                                0.5 * h_rtt;

#ifdef WITH_MYSQL
                gw_update_pings(gw, link, h_rtt);
#endif
            }
        }
    }

    return SUCCESS;
}


