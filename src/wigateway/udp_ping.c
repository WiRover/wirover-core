#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#ifdef SUPPORT_ICMP_PING
#include <netinet/ip_icmp.h>
#endif

#include "gpsHandler.h"
#include "../common/link.h"
#include "../common/debug.h"
#include "../common/special.h"
#include "../common/contChan.h"
#include "../common/udp_ping.h"

/* Remote ping target to be used by sendPing. */
static struct sockaddr  ping_dest;
static socklen_t        ping_dest_len = 0;

void setUdpPingTarget(const struct sockaddr *dest, socklen_t dest_len)
{
    ping_dest = *dest;
    ping_dest_len = dest_len;
}

/*
 * O P E N   P I N G   S O C K E T
 *
 * Creates a socket for sending and receiving UDP pings.  If localPort is 0, it
 * binds to an arbitrary free port.  Returns -1 on failure or the socket file
 * descriptor.
 */
static int openPingSocket(unsigned short localPort, const char* bindDevice)
{
#ifdef SUPPORT_ICMP_PING
    int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
#else
    int sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return -1;
    }

    // Allow multiple sockets to bind to the port
    int yes = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        DEBUG_MSG("setsockopt() SO_REUSEADDR failed");
        close(sockfd);
        return -1;
    }

    //TODO: Add IPv6 capability
    struct sockaddr_in bindAddr;
    bzero(&bindAddr, sizeof(struct sockaddr_in));
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(localPort);
    bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(sockfd, (struct sockaddr*)&bindAddr,
            sizeof(struct sockaddr_in)) < 0) {
        ERROR_MSG("binding socket failed");
        close(sockfd);
        return -1;
    }

    // Bind socket to device
    if(bindDevice && setsockopt(sockfd, SOL_SOCKET,
       SO_BINDTODEVICE, bindDevice, IFNAMSIZ) < 0) {
        DEBUG_MSG("setsockopt() SO_BINDTODEVICE failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
} /* end function createPingSocket */

#ifdef SUPPORT_ICMP_PING
/* Calculate ICMP packet checksum */
static unsigned short icmp_cksum(char *data, int len)
{
    unsigned int sum;
    unsigned short *w = (void *)data;

    for(sum = 0; len > 1; len -= 2)
        sum += *w++;
    if(len == 1)
        sum += ((unsigned short)(*(unsigned char *)w) << 8);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}
#endif

/*
 * Send a ping packet to the target set by setUdpPingTarget.
 * Depends on configuration, could go through traditional ICMP or UDP.
 */
int sendPing(struct link *link)
{
    // Open new socket if needed
    if(link->ping_socket < 0)
        if((link->ping_socket = openPingSocket(0, link->ifname)) == -1)
            return FAILURE;

#ifdef SUPPORT_ICMP_PING
    // Send via ICMP packet, fill in the packet content
    char buffer[sizeof(struct icmp) + sizeof(struct timeval)];
    bzero(buffer, sizeof(buffer));

    struct icmp *icmp = (void *)buffer;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_seq = 0; // TODO: put a sequence number here
    icmp->icmp_id  = htons(getpid() & 0xFFFF);

    struct timeval *timestamp = (void *)(icmp + 1);
    gettimeofday(timestamp, 0);
    icmp->icmp_cksum = icmp_cksum(buffer, sizeof(buffer));
#else
    // Send via UDP packet, fill in the tunnel header.
    char buffer[sizeof(struct tunhdr) + sizeof(struct ping_pkt)];
    bzero(buffer, sizeof(buffer));

    struct tunhdr *tun_hdr = (void *)buffer;
    tun_hdr->seq_no = SPECIAL_PKT_SEQ_NO;
    tun_hdr->node_id = htons(getNodeID());
    tun_hdr->link_id = htons(link->id);
    tun_hdr->local_seq_no   = 0; //TODO: Should we use this field?
    // No passive measurements on ping packets because it is tricky on the
    // controller side.
    tun_hdr->send_ts = getTunnelTimestamp(0);
    tun_hdr->recv_ts = TUNHDR_NO_TIMESTAMP;
    tun_hdr->service = TUNHDR_NO_TIMESTAMP;

    // Create the body of the ping packet
    // Embed GPS data into the packet, if enabled
    struct ping_pkt *ping_pkt = (void *)(tun_hdr + 1);
    ping_pkt->type = htons(SPKT_UDP_PING);
    fillGpsPayload(&ping_pkt->gps);

    // Store timestamp in packet
    struct timeval send_tv;
    gettimeofday(&send_tv, 0);
    ping_pkt->sent_time_sec = htonl(send_tv.tv_sec);
    ping_pkt->sent_time_usec = htonl(send_tv.tv_usec);
#endif
    // Send ping packet now
    if(sendto(link->ping_socket, buffer,
                sizeof(buffer), 0, &ping_dest, ping_dest_len) < 0) {
        // The error here may have resulted from the interface going down,
        // force reopen the socket.
        ERROR_MSG("sendto() failed");
        close(link->ping_socket);
        link->ping_socket = -1;
        return FAILURE;
    }
    return SUCCESS;
}

#ifndef SUPPORT_ICMP_PING
/* Send ping response packet */
int sendPingStats(struct link *link, struct ping_stats *stats,
        const struct sockaddr *dest, socklen_t dest_len)
{
    char buffer[sizeof(struct tunhdr) + sizeof(struct ping_stats_pkt)];
    bzero(buffer, sizeof(buffer));

    // Fill in the tunnel header
    struct tunhdr *tun_hdr = (void *)buffer;
    tun_hdr->seq_no = SPECIAL_PKT_SEQ_NO;
    tun_hdr->node_id = htons(getNodeID());
    tun_hdr->link_id = htons(link->id);
    tun_hdr->local_seq_no = 0; //TODO: Should we use this field?
    // No passive measurements on ping packets because it is tricky on the
    // controller side.
    tun_hdr->send_ts        = getTunnelTimestamp(0);
    tun_hdr->recv_ts        = TUNHDR_NO_TIMESTAMP;
    tun_hdr->service        = TUNHDR_NO_TIMESTAMP;
    tun_hdr->prev_len       = 0;

    // Create the body of the ping packet
    struct ping_stats_pkt *ping_pkt = (void *)(tun_hdr + 1);
    ping_pkt->type  = htons(SPKT_PING_STATS);
    ping_pkt->rtt   = htonl(stats->rtt);

    if(sendto(link->ping_socket, buffer,
                sizeof(buffer), 0, dest, dest_len) < 0) {
        ERROR_MSG("UDP ping response sendto() failed");
        return FAILURE;
    }

    return SUCCESS;
}
#endif

/*
 * R E G I S T E R   P I N G   C A L L B A C K
 *
 * Register a function to be called whenever a ping is completed.
 * This includes timeouts.
 *
 * Beware!  Only one callback function is currently supported.
 */
void registerPingCallback(
        struct ping_client_info* clientInfo, ping_callback_t func) {
    if(clientInfo)
        clientInfo->callback = func;
}

/* Ping reception handling routine. */
static int handlePingResponse(struct ping_client_info *clientInfo, struct link *link)
{
    // Receive packet and record reception time
#ifdef SUPPORT_ICMP_PING
    char buffer[sizeof(struct iphdr) +
                sizeof(struct icmp) + sizeof(struct timeval)];
#else
    char buffer[sizeof(struct tunhdr) + sizeof(struct ping_pkt)];
#endif
    struct sockaddr from;
    socklen_t fromSize = sizeof(from);
    int bytes = recvfrom(link->ping_socket, buffer,
                            sizeof(buffer), 0, &from, &fromSize);
   if(bytes < 0) {
        ERROR_MSG("recvfrom() failed");
        return FAILURE;
    } else if(bytes < sizeof(buffer)) {
        DEBUG_MSG("ping packet received was too short");
        return FAILURE;
    } else
        DEBUG_MSG("ping packet received: %lu bytes", sizeof(buffer));

    struct timeval recv_tv;
    if(ioctl(link->ping_socket, SIOCGSTAMP, &recv_tv) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        return FAILURE;
    }

    struct ping_stats stats;
    bzero(&stats, sizeof(stats));

#ifdef SUPPORT_ICMP_PING
    // ICMP ping packet received
    struct iphdr *iphdr = (void *)buffer;
    struct icmp *icmp = (void *)(iphdr + 1);
    struct timeval *send_tv = (void *)(icmp + 1);

    if(icmp->icmp_type == ICMP_ECHOREPLY &&
       ntohs(icmp->icmp_id) == (getpid() & 0xFFFF)) {
        stats.rtt = (recv_tv.tv_sec - send_tv->tv_sec) * 1000000 +
                    (recv_tv.tv_usec - send_tv->tv_usec);
        if(clientInfo->callback)
            return clientInfo->callback(clientInfo, link, &stats);
    }
#else
    // UDP ping packet received
    struct tunhdr *tun_hdr = (void *)buffer;
    struct ping_pkt *ping_pkt = (void *)(tun_hdr + 1);

    // Verify that the received packet is the one we expect
    if(ntohl(tun_hdr->seq_no) == SPECIAL_PKT_SEQ_NO &&
       ntohs(tun_hdr->link_id) == link->id) {
        int h_sent_sec  = ntohl(ping_pkt->sent_time_sec);
        int h_sent_usec = ntohl(ping_pkt->sent_time_usec);
        int h_rcvd_sec  = ping_pkt->rcvd_time.tv_sec;
        int h_rcvd_usec = ping_pkt->rcvd_time.tv_usec;

        // Compute round-trip time in microseconds
        stats.rtt = (recv_tv.tv_sec - h_sent_sec) * 1000000 +
                    (recv_tv.tv_usec - h_sent_usec);
        stats.t_ul = (h_rcvd_sec - h_sent_sec) * 1000 +
                     (h_rcvd_usec - h_sent_usec) / 1000;

        sendPingStats(link, &stats, &from, fromSize);
        if(clientInfo->callback)
            return clientInfo->callback(clientInfo, link, &stats);
    }
#endif
    return SUCCESS;
}

/*
 * P I N G   T H R E A D   F U N C
 *
 */
void* pingThreadFunc(void* clientInfo)
{
    struct ping_client_info* info = clientInfo;
    struct timeval currTime_tv, lastPingTest_tv, maxInterval_tv;
    timerclear(&lastPingTest_tv);
    maxInterval_tv.tv_sec = info->interval / 1000000;
    maxInterval_tv.tv_usec = info->interval % 1000000;

    // Block SIGALRM so that it does not interrupt our socket calls.
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &sigset, 0);

    while(!getQuitFlag()) {
        int max_fd = -1;
        struct link *link;
        struct timeval select_tv;
        fd_set read_set;
        FD_ZERO(&read_set);

        // Check if it is time to run another ping test.
        gettimeofday(&currTime_tv, 0);
        timersub(&currTime_tv, &lastPingTest_tv, &select_tv);

        if(!timercmp(&select_tv, &maxInterval_tv, <)) {
            // XXX race condition
            for(link = head_link__; link; link = link->next) {
                if(link->state != DEAD) {
                    if(sendPing(link) == SUCCESS) {
                        FD_SET(link->ping_socket, &read_set);
                        if(link->ping_socket > max_fd)
                            max_fd = link->ping_socket;
                    }
                }
            }

            lastPingTest_tv = currTime_tv;
            select_tv = maxInterval_tv;
        }

        int ready = select(max_fd + 1, &read_set, 0, 0, &select_tv);

        if(ready == -1) {
            // EINTR is likely due to SIGINT or SIGTERM - program is to terminate.
            // Any other failure case must be investigated.
            if(errno != EINTR)
                ERROR_MSG("select call failed");
            break;
        } else if(ready > 0) {
            // XXX race condition
            for(link = head_link__; link; link = link->next)
                if(link->ping_socket >= 0 &&
                   FD_ISSET(link->ping_socket, &read_set))
                    handlePingResponse(info, link);
        }
    }

    return NULL;
}


/*
 * S T A R T   P I N G   C L I E N T   T H R E A D
 *
 * Starts a thread for sending and receiving UDP pings.
 *
 * Returns SUCCESS or FAILURE.
 */
int startPingClientThread(struct ping_client_info* clientInfo)
{
    clientInfo->callback = NULL;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if(pthread_create(&clientInfo->thread, &attr,
                        pingThreadFunc, clientInfo) != 0) {
        DEBUG_MSG("pthread_create failed");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);
    return SUCCESS;
} /* end function initPingThread */

// vim: set et ts=4 sw=4:
