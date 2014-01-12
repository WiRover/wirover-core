#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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
#include "../common/sockets.h"
#include "../common/special.h"
#include "../common/time_utils.h"
#include "../common/utils.h"
#include "../common/active_bw.h"

// Internal functions
void*   bandwidthServerFunc(void* serverInfo);
void*   bandwidthServerFunc_udp(void* serverInfo);
int     openBandwidthServerSocket(const struct bw_server_info* serverInfo);
int     openBandwidthServerSocket_udp(const struct bw_server_info* serverInfo);
int     handleBandwidthClient(const struct bw_server_info* serverInfo, int serverSocket);
int     handleBandwidthClient_udp(const struct bw_server_info* serverInfo, int serverSocket);
int     sendCts(int sockfd);
int     sendCts_udp(int sockfd, struct sockaddr_in hisAddr);
unsigned int    getTransferSizeBits(unsigned int payloadBytes);
int recvfromClientBurst_timeout(int socket, void* buffer, size_t len, int flags,
        struct timespec* timeout, struct timeval* recvTime);


int startBandwidthServerThread(struct bw_server_info* serverInfo)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if(pthread_create(&serverInfo->tcp_thread, &attr, bandwidthServerFunc, serverInfo) != 0) {
        DEBUG_MSG("failed to create bandwidth server thread");
        return FAILURE;
    }

    if(pthread_create(&serverInfo->udp_thread, &attr, bandwidthServerFunc_udp, serverInfo) != 0) {
        DEBUG_MSG("failed to create udp bandwidth server thread");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);
    return SUCCESS;
}

void* bandwidthServerFunc(void* serverInfo)
{
    struct bw_server_info* info = (struct bw_server_info*)serverInfo;

    int sockfd = openBandwidthServerSocket(info);
    if(sockfd < 0) {
        return 0;
    }
        
    
    if(listen(sockfd, SOMAXCONN) < 0) {
        ERROR_MSG("listen failed");
        close(sockfd);
        return 0;
    }

    while(!getQuitFlag()) {
          handleBandwidthClient(info, sockfd);
    }

    close(sockfd);
    return 0;
}


void* bandwidthServerFunc_udp(void* serverInfo)
{
    struct bw_server_info* info = (struct bw_server_info*)serverInfo;

    int sockfd = openBandwidthServerSocket_udp(info);
    DEBUG_MSG("udp sockfd:%d",sockfd);
    if(sockfd < 0) {
        return 0;
    }

    while(!getQuitFlag()) {
        int rtn = handleBandwidthClient_udp(info, sockfd);
        DEBUG_MSG("handleBWclient_udp :%d",rtn);
    }

    close(sockfd);
    return 0;
}


int openBandwidthServerSocket(const struct bw_server_info* serverInfo)
{
    int sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return -1;
    }

    // Allow multiple sockets to bind to the port
    const int yes = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        DEBUG_MSG("SO_REUSEADDR failed");
        close(sockfd);
        return -1;
    }

    struct sockaddr_in bindAddr;
    memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.sin_family         = AF_INET;
    bindAddr.sin_port           = htons(serverInfo->local_port);
    bindAddr.sin_addr.s_addr    = htonl(INADDR_ANY);

    if(bind(sockfd, (struct sockaddr*)&bindAddr, sizeof(struct sockaddr_in)) < 0) {
        ERROR_MSG("binding socket failed");
        close(sockfd);
        return -1;
    }

    return sockfd; 
}

int openBandwidthServerSocket_udp(const struct bw_server_info* serverInfo)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return -1;
    }

    // Allow multiple sockets to bind to the port
    const int yes = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        DEBUG_MSG("SO_REUSEADDR failed");
        close(sockfd);
        return -1;
    }

    struct sockaddr_in bindAddr;
    memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.sin_family         = AF_INET;
    bindAddr.sin_port           = htons(serverInfo->local_port);
    bindAddr.sin_addr.s_addr    = htonl(INADDR_ANY);

    if(bind(sockfd, (struct sockaddr*)&bindAddr, sizeof(struct sockaddr_in)) < 0) {
        ERROR_MSG("binding socket failed");
        close(sockfd);
        return -1;
    }

    return sockfd; 
}


int handleBandwidthClient(const struct bw_server_info* serverInfo, int serverSocket)
{
    struct sockaddr_in  hisAddr;
    socklen_t addrLen = sizeof(hisAddr);
    int rtn = 0;
    int bytesSent;
    int bytesRecvd;
    struct timespec     tspec;

    const int header_size = sizeof(struct tunhdr) + sizeof(struct bw_hdr);
    char header_buffer[header_size];
    char* buffer = 0;

    int client_sock = accept(serverSocket, (struct sockaddr*)&hisAddr, &addrLen);
    if(client_sock < 0) {
        ERROR_MSG("accept failed");
        goto handle_client_fail;
    }

    struct timeval timeout;
    set_timeval_us(&timeout, serverInfo->timeout);

    rtn = setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if(rtn < 0) {
        ERROR_MSG("setsockopt SO_RCVTIMEO failed");
        goto handle_client_fail;
    }

    rtn = sendCts(client_sock);
    DEBUG_MSG("sendCts:%d", rtn);
    if(rtn == FAILURE) {
        goto handle_client_fail;
    }

    tspec.tv_sec  = serverInfo->timeout / 1000000;
    tspec.tv_nsec = (serverInfo->timeout % 1000000) * 1000;

    struct timeval elapsed_a;
    bytesRecvd = recv_timeout(client_sock, header_buffer, header_size, MSG_WAITALL,
                                 &tspec, &elapsed_a);
    DEBUG_MSG("bytesRecvd:%d", bytesRecvd);
    if(bytesRecvd < header_size) {
        goto handle_client_fail;
    }

    struct bw_hdr* bw_hdr;
    bw_hdr = (struct bw_hdr*)(header_buffer + sizeof(struct tunhdr));
    const unsigned int h_numBytes = ntohl(bw_hdr->size);

    if(h_numBytes > MAX_BW_BYTES) {
        DEBUG_MSG("Bandwidth client requested an unusually large stream");
        goto handle_client_fail;
    } else if(h_numBytes < header_size) {
        DEBUG_MSG("Bandwidth client requested an unusually small stream");
        goto handle_client_fail;
    }

    buffer = (char*)malloc(h_numBytes);
    if(!buffer) {
        DEBUG_MSG("malloc failed");
        goto handle_client_fail;
    }
    memcpy(buffer, header_buffer, header_size);
    
    tspec.tv_sec  = serverInfo->timeout / 1000000;
    tspec.tv_nsec = (serverInfo->timeout % 1000000) * 1000;

    struct timeval elapsed_b;

    // MSG_WAITALL should force recv to block until the entire stream has been
    // received or (hopefully) until the socket's timeout has been hit, set by
    // setsockopt
    rtn = recv_timeout(client_sock, (buffer + header_size), (h_numBytes - header_size), MSG_WAITALL,
                          &tspec, &elapsed_b);
    DEBUG_MSG("recv_timeout:%d",rtn);
    if(rtn < (h_numBytes - header_size)) {
        goto handle_client_fail;
    }
    
    bw_hdr = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));

    const unsigned int numBits = getTransferSizeBits(h_numBytes);

    // This is the bandwidth from the gateway to the controller
    int elapsed_us = (elapsed_a.tv_sec * 1000000) + elapsed_a.tv_usec +
                     (elapsed_b.tv_sec * 1000000) + elapsed_b.tv_usec;

    double gw_uplink_bw = (double)numBits / elapsed_us; //in mbps
    bw_hdr->bandwidth = gw_uplink_bw;

    bytesSent = send(client_sock, buffer, h_numBytes, 0);
    if(bytesSent < 0) {
        ERROR_MSG("bandwidth send failed");
        goto handle_client_fail;
    } else if(bytesSent < h_numBytes) {
        goto handle_client_fail;
    }
    
    tspec.tv_sec  = serverInfo->timeout / 1000000;
    tspec.tv_nsec = (serverInfo->timeout % 1000000) * 1000;

    rtn = recv_timeout(client_sock, header_buffer, header_size, MSG_WAITALL,
                       &tspec, 0);
    DEBUG_MSG("recv_timeout:%d",rtn);
    if(rtn < header_size) {
        goto handle_client_fail;
    }

    struct tunhdr* tun_hdr = (struct tunhdr*)header_buffer;
    bw_hdr = (struct bw_hdr*)(header_buffer + sizeof(struct tunhdr));

    unsigned short h_node_id = ntohs(tun_hdr->node_id);
    unsigned short h_link_id = ntohs(tun_hdr->link_id);

    // This is the bandwidth from the controller to the gateway
    double gw_downlink_bw = bw_hdr->bandwidth;
    
    STATS_MSG("Bandwidth for node %d link %d down: %f mbps, up: %f mbps, bytes: %u, bits: %u",
            h_node_id, h_link_id, gw_downlink_bw, gw_uplink_bw, h_numBytes, numBits);

    // Update the bandwidth field (currently, we only care about the gateway's
    // downlink bandwidth
    struct wigateway* gw = searchWigatewaysByNodeID(h_node_id);
    if(gw) {
        time(&gw->last_seen_pkt_time);

        struct link* link = searchLinksById(gw->head_link, h_link_id);
        if(link) {
            updateLinkBandwidth(link, gw_downlink_bw, gw_uplink_bw);

#ifdef WITH_MYSQL
            gw_update_activebw(gw, link, BW_TCP, gw_downlink_bw, gw_uplink_bw);
#endif
        }

        computeLinkWeights(gw->head_link);
    }

    free(buffer);
    close(client_sock);

    return SUCCESS;

handle_client_fail:
    if(buffer) {
        free(buffer);
    }

    if(client_sock != -1) {
        close(client_sock);
    }

    return FAILURE;
}

int handleBandwidthClient_udp(const struct bw_server_info* serverInfo, int sockfd)
{
    struct sockaddr_in  hisAddr;
    socklen_t addrLen = sizeof(struct sockaddr);
    int rtn = 0, bytesSent=0;
    struct timespec     tspec;

    const int header_size = sizeof(struct tunhdr) + sizeof(struct bw_hdr);
    const int packet_size = sizeof(struct bw_hdr);
    char header_buffer[MTU];


    DEBUG_MSG("At recvfrom");
    rtn = recvfrom(sockfd, header_buffer, packet_size, MSG_WAITALL, (struct sockaddr*)&hisAddr, &addrLen);
    DEBUG_MSG("Rcvd RTS:%d",rtn); 

    rtn = sendCts_udp(sockfd, hisAddr);
    DEBUG_MSG("sendCts:%d", rtn);
    if(rtn == FAILURE) {
        return FAILURE;
    }

    tspec.tv_sec  = serverInfo->timeout / 1000000;
    tspec.tv_nsec = (serverInfo->timeout % 1000000) * 1000;

    struct bw_hdr* bw_hdr;
    int h_numBytes = DEFAULT_MTU;

    char buffer[h_numBytes];

    struct timeval elapsed_b;

    // MSG_WAITALL should force recv to block until the entire stream has been
    // received or (hopefully) until the socket's timeout has been hit, set by
    // setsockopt
    rtn = recvfromClientBurst_timeout(sockfd, buffer, h_numBytes, MSG_WAITALL,
                          &tspec, &elapsed_b);
  
    const unsigned int numBits = getTransferSizeBits(rtn);

    // This is the bandwidth from the gateway to the controller
    int elapsed_us =  (elapsed_b.tv_sec * 1000000) + elapsed_b.tv_usec;

    double gw_uplink_bw = (double)(rtn*8)/ elapsed_us; //in mbps
    DEBUG_MSG("bytes:%d, time:%d, uplink_bw: %f mbps",rtn, elapsed_us,gw_uplink_bw);



   //Send Packets for DL BW estimation by Client
    int i;

    
    for(i=0; i<=19; i++){
    //  buffer += i*DEFAULT_MTU;

    bw_hdr = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));
    bw_hdr->bandwidth = gw_uplink_bw;
    
    rtn = sendto(sockfd, buffer, DEFAULT_MTU, 0, (struct sockaddr*)&hisAddr, sizeof(hisAddr));
    bytesSent += rtn;
    //DEBUG_MSG("sent packet %d, %d", i, rtn);
    }

    DEBUG_MSG("bytesSent:%d",bytesSent);

    sleep(ACTIVE_BW_TIMEOUT/1000000);

    tspec.tv_sec  = serverInfo->timeout / 1000000;
    tspec.tv_nsec = (serverInfo->timeout % 1000000) * 1000;

    rtn = recvfrom_timeout(sockfd, header_buffer, header_size, MSG_WAITALL,
                       &tspec, 0);
    if(rtn < header_size) {
        return FAILURE;
    }

    struct tunhdr* tun_hdr = (struct tunhdr*)header_buffer;
    bw_hdr = (struct bw_hdr*)(header_buffer + sizeof(struct tunhdr));

    unsigned short h_node_id = ntohs(tun_hdr->node_id);
    unsigned short h_link_id = ntohs(tun_hdr->link_id);

    // This is the bandwidth from the controller to the gateway
    double gw_downlink_bw = bw_hdr->bandwidth;
    
    STATS_MSG("Bandwidth for node %d link %d down: %f mbps, up: %f mbps, bytes: %d, bits: %u",
            h_node_id, h_link_id, gw_downlink_bw, gw_uplink_bw, h_numBytes, numBits);

    // Update the bandwidth field (currently, we only care about the gateway's
    // downlink bandwidth
    struct wigateway* gw = searchWigatewaysByNodeID(h_node_id);
    if(gw) {
        time(&gw->last_seen_pkt_time);

        struct link* link = searchLinksById(gw->head_link, h_link_id);
        if(link) {
            updateLinkBandwidth(link, gw_downlink_bw, gw_uplink_bw);

#ifdef WITH_MYSQL
            gw_update_activebw(gw, link, BW_UDP, gw_downlink_bw, gw_uplink_bw);
#endif
        }

        computeLinkWeights(gw->head_link);
    }

   // close(sockfd);

    return SUCCESS;
}

/*
 * RECEIVE CTS
 *
 * Waits up to timeout microseconds for a CTS packet.  If this returns SUCCESS,
 * then you are clear to flood the server with useless data.  If max_burst is
 * not null, this will write the server's max burst size into it.  If you try
 * to send more than that the server will ignore you.
 *

static int receiveRts(int sockfd, int timeout, unsigned int* max_burst)
{
    const int packet_size = sizeof(struct bw_hdr);
    char buffer[packet_size];
    int result;

    struct sockaddr_in hisAddr;

    result = recvfrom(sockfd, buffer, packet_size, MSG_WAITALL, (struct sockaddr*)&hisAddr, sizeof(hisAddr));
    
   if(result < packet_size) {
        if(result == -1 && errno == EWOULDBLOCK) {
            DEBUG_MSG("Timed out receiving CTS");
        }
        return FAILURE;
    }

    struct bw_hdr* __restrict__ bw_hdr = (struct bw_hdr*)buffer;
    uint16_t h_type = ntohs(bw_hdr->type);
    uint32_t h_size = ntohl(bw_hdr->size);

   if(h_type != SPKT_ACTBW_CTS) {
        DEBUG_MSG("Received something other than CTS... look into this");
        return FAILURE;
    }

    if(max_burst) {
        *max_burst = h_size;
    }

    return SUCCESS;
}
*/



/*
 * SEND CTS
 *
 * Sends a Clear-to-Send (CTS) message to the bandwidth client.
 */
int sendCts(int sockfd)
{
    const unsigned int packet_size = sizeof(struct bw_hdr);
    char buffer[packet_size];
    memset(buffer, 0, sizeof(buffer));

    struct bw_hdr* __restrict__ bw_hdr = (struct bw_hdr*)buffer;
    bw_hdr->type = htons(SPKT_ACTBW_CTS);
    bw_hdr->size = htonl(MAX_BW_BYTES);
    bw_hdr->bandwidth = 0.0;

    int rtn = send(sockfd, buffer, packet_size, 0);
    if(rtn < 0) {
        ERROR_MSG("Sending CTS failed");
        return FAILURE;
    } else if(rtn < packet_size) {
        DEBUG_MSG("Sending CTS stopped early");
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * SEND CTS_UDP
 *
 * Sends a Clear-to-Send (CTS) message to the bandwidth client.
 */
int sendCts_udp(int sockfd, struct sockaddr_in hisAddr)
{
    const unsigned int packet_size = sizeof(struct bw_hdr);
    char buffer[packet_size];
    memset(buffer, 0, sizeof(buffer));

    struct bw_hdr* __restrict__ bw_hdr = (struct bw_hdr*)buffer;
    bw_hdr->type = htons(SPKT_ACTBW_CTS);
    bw_hdr->size = htonl(MAX_BW_BYTES);
    bw_hdr->bandwidth = 0.0;

    int rtn = sendto(sockfd, buffer, packet_size, 0, (struct sockaddr*)&hisAddr, sizeof(hisAddr));
    if(rtn < 0) {
        ERROR_MSG("Sending CTS failed");
        return FAILURE;
    } else if(rtn < packet_size) {
        DEBUG_MSG("Sending CTS stopped early");
        return FAILURE;
    }

    return SUCCESS;
}


int recvfromClientBurst_timeout(int socket, void* buffer, size_t len, int flags, struct timespec* timeout, struct timeval* recvTime)
{
    int         result;
    fd_set      readSet;
    sigset_t    sigset;
    int         retval = 0, ret =0, flag=0;
    struct bw_hdr* __restrict__ bw_hdr;
    
    if(!timeout) {
        retval = recvfrom(socket, buffer, DEFAULT_MTU, flags, NULL, 0);
        goto done;
    }

    FD_ZERO(&readSet);
    FD_SET(socket, &readSet);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);

    struct timeval  startTime;
   
   while(1){
    result = pselect(socket + 1, &readSet, 0, 0, timeout, &sigset);
    //DEBUG_MSG("pselect result:%d",result);

    if(result < 0) {
        retval = -1;
        goto done;
    } else if(!FD_ISSET(socket, &readSet)) {
        // Receive timed out
        errno = EWOULDBLOCK;
        //retval = -1;
        goto done;
    }
    
    struct timeval  prevRecvTimeout;
    struct timeval  tempRecvTimeout = {
        .tv_sec     = timeout->tv_sec,
        .tv_usec    = timeout->tv_nsec / 1000,
    };

    //TODO: Check return values of {get,set}sockopt()
    socklen_t       timeoutSize = sizeof(prevRecvTimeout);
    getsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, &timeoutSize);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tempRecvTimeout, sizeof(tempRecvTimeout));



    ret = recvfrom(socket, buffer, len, flags, NULL, 0);


    bw_hdr = (struct bw_hdr*)((char *)buffer + sizeof(struct tunhdr));
    DEBUG_MSG("RcvdPkt: %d",(int)bw_hdr->bandwidth);

    // Set StartTime after receiving First Packet
    if (!flag){
    flag=1;
    gettimeofday(&startTime,0);
    }
    else {
    retval += ret;
    }

    struct timeval  endTime;
    if(recvTime) {
        gettimeofday(&endTime, 0);
        timeval_diff(recvTime, &startTime, &endTime);
    }

    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, sizeof(prevRecvTimeout));
  }
done:
    return retval;

}

/*
 * GET TRANSFER SIZE BITS
 *
 * Estimates the number of bits in sending the payload over TCP.  Assumes a
 * default MTU to calculate how many bits are transmitted for IP and TCP
 * headers.
 */
unsigned int getTransferSizeBits(unsigned int payloadBytes)
{
    const int payloadMtu = DEFAULT_MTU - DEFAULT_IP_H_SIZE - DEFAULT_TCP_H_SIZE;
    unsigned int numPackets = (unsigned int)ceil((double)payloadBytes / payloadMtu);
    unsigned int numBytes = payloadBytes + 
        (DEFAULT_IP_H_SIZE + DEFAULT_TCP_H_SIZE) * numPackets;
    return numBytes * 8;
}

// vim: set et ts=4 sw=4:

