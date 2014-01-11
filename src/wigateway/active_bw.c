#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

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
void*   bandwidthThreadFunc(void* clientInfo);
int     runActiveBandwidthTest(struct bw_client_info* clientInfo, struct bw_stats* stats);
int     runActiveBandwidthTest_udp(struct bw_client_info* clientInfo, struct bw_stats* stats);

static int  openBandwidthSocket(struct bw_client_info* clientInfo, const char* bindDevice);
static int  openBandwidthSocket_udp(struct bw_client_info* clientInfo, const char* bindDevice);
static int  receiveCts(int sockfd, int timeout, unsigned int* max_burst);
static int  receiveCts_udp(int sockfd, int timeout, unsigned int* max_burst);
static int  sendBurst(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats);
static int  sendBurst_udp(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats);
static int  receiveBurst(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats);
static int  receiveBurst_udp(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats);
static int  sendMeasurement(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats);
static int  sendMeasurement_udp(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats);
static unsigned int    getTransferSizeBits(unsigned int payloadBytes);


/*
 * S T A R T   B A N D W I D T H   T H R E A D
 *
 * Starts a thread that will continually run bandwidth tests.  
 *
 * The caller must pass a pointer to a bw_client_info structure that has the
 * settings fields properly set.
 *
 * Returns SUCCESS or FAILURE.
 */
int startBandwidthClientThread(struct bw_client_info* clientInfo)
{
    assert(clientInfo != 0);
    
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    // initialize private fields of the structure
    clientInfo->callback = 0;
    clientInfo->pauseFlag = 0;

    pthread_mutex_init(&clientInfo->pauseMutex, 0);
    pthread_cond_init(&clientInfo->pauseCond, 0);

    int rtn = pthread_create(&clientInfo->thread, &attr, bandwidthThreadFunc, clientInfo);
    if(rtn != 0) {
        ERROR_MSG("failed to create bandwidth thread");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);
    
    return SUCCESS;
} // end function startBandwidthThread()

/*
 * R E G I S T E R   B A N D W I D T H   C A L L B A C K
 *
 * Sets the function to be called whenever a bandwidth test is completed.
 *
 * Note: The current implementation only supports one callback.
 */
void registerBandwidthCallback(struct bw_client_info* clientInfo, bw_callback_t callback)
{
    assert(clientInfo != 0);
    clientInfo->callback = callback;
}

/*
 * S E T   B A N D W I D T H   I N T E R V A L
 *
 * Sets the interval for bandwidth tests.  The interval should be in
 * microseconds.
 *
 */
void setBandwidthInterval(struct bw_client_info* clientInfo, unsigned int interval)
{
    assert(clientInfo != 0);
    clientInfo->interval = interval;
}

/*
 * P A U S E   B A N D W I D T H   T H R E A D
 *
 * Pauses execution of the active bandwidth tests until resumeBandwidthThread()
 * is called.
 */
void pauseBandwidthThread(struct bw_client_info* clientInfo)
{
    clientInfo->pauseFlag = 1;
}

/*
 * R E S U M E   B A N D W I D T H   T H R E A D
 *
 * Resumes execution of the active bandwidth tests.
 */
void resumeBandwidthThread(struct bw_client_info* clientInfo)
{
    if(clientInfo->pauseFlag) {
        pthread_mutex_lock(&clientInfo->pauseMutex);
        clientInfo->pauseFlag = 0;
        pthread_cond_signal(&clientInfo->pauseCond);
        pthread_mutex_unlock(&clientInfo->pauseMutex);
    }
}

/*
 * B A N D W I D T H   T H R E A D   F U N C
 *
 */
void* bandwidthThreadFunc(void* clientInfo)
{
    struct bw_client_info* info = (struct bw_client_info*)clientInfo;

    // Let another thread handle these signals
    // We don't want them to interrupt our socket calls
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &sigset, 0);

    while(!getQuitFlag()) {
        // Put the thread to sleep if we want to pause active bandwidth measurements
        if(info->pauseFlag) {
            pthread_mutex_lock(&info->pauseMutex);
            while(info->pauseFlag) {
                pthread_cond_wait(&info->pauseCond, &info->pauseMutex);
            }
            pthread_mutex_unlock(&info->pauseMutex);
        }

        struct link* ife = head_link__;
        while(ife) {
            if(ife->state != DEAD) {
                struct bw_stats stats;
                memcpy(stats.device, ife->ifname, IFNAMSIZ);
                stats.link_id = ife->id;
                
                int rtn;
 
                switch(BW_TYPE){
                case BW_TCP:
                    rtn = runActiveBandwidthTest(info, &stats);
                    break;
                case BW_UDP:
                    rtn = runActiveBandwidthTest_udp(info, &stats);
                    DEBUG_MSG("runActiveBandwidthTest_udp: %d", rtn);
                    break;
                default:
                     break;
                }            
 
                if(rtn == SUCCESS && info->callback != 0) {
                    info->callback(clientInfo, ife, &stats);
                }

                // Give some time for the connection to be torn down and
                // perhaps for other gateways to access the server.
                safe_usleep(ACTIVE_BW_DELAY);
            }

            ife = ife->next;
        }

        safe_usleep(info->interval);
    }

    return 0;
}

/*
 * R U N   A C T I V E   B A N D W I D T H   T E S T
 *
 * Runs a bandwidth test by transferring a random file (a large, contiguous
 * block of data).  This consists of opening a TCP connection, sending the
 * data, then receiving the same data again.
 *
 * Returns SUCCESS or FAILURE.  SUCCESS is returned only if the entire test is
 * completed and the uplink and downlink measurements are available.
 */
int runActiveBandwidthTest_udp(struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    int  sockfd_data = -1;
    int rtn;
    const int header_size = sizeof(struct tunhdr) + sizeof(struct bw_hdr);
    const int burst_size = DEFAULT_MTU;
    const int packet_size = sizeof(struct bw_hdr);

    // The burst needs to fit the header at least.
    assert(burst_size >= header_size);
    char buffer_burst[burst_size];
    
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family       = AF_INET;
    remoteAddr.sin_port         = htons(clientInfo->remote_port);
    remoteAddr.sin_addr.s_addr  = clientInfo->remote_addr;

    char buffer[packet_size];
    memset(buffer, 0, sizeof(buffer));

    struct bw_hdr* bw_hdr = (struct bw_hdr*)buffer;
    bw_hdr->type = htons(SPKT_ACTBW_CTS);
    bw_hdr->size = htonl(MAX_BW_BYTES);
    bw_hdr->bandwidth = 0.0;
    socklen_t addrLen = sizeof(struct sockaddr);

    sockfd_data = openBandwidthSocket_udp(clientInfo, stats->device);
    if(sockfd_data == -1)
        goto err_out;
   
    rtn = sendto(sockfd_data, buffer, packet_size, 0, (struct sockaddr*)&remoteAddr, addrLen);
    if(rtn < 0) {
        ERROR_MSG("Sending RTS failed");
        goto err_out_close_sockfd;
    } else if(rtn < packet_size) {
        DEBUG_MSG("Sending RTS stopped early");
        goto err_out_close_sockfd;
    }

    // Wait for CTS
 
    unsigned int max_burst;
    rtn = receiveCts_udp(sockfd_data, clientInfo->timeout, &max_burst);
    if(rtn == FAILURE) {
        goto err_out_close_sockfd;
    }

    fillBufferRandom(buffer_burst, burst_size);

    rtn = sendBurst_udp(sockfd_data, buffer_burst, burst_size, clientInfo, stats); 
    if(rtn <= 0)
        goto err_out_close_sockfd;

    sleep (ACTIVE_BW_TIMEOUT/1000000);
    rtn = receiveBurst_udp(sockfd_data, buffer_burst, burst_size, clientInfo, stats);
    if(rtn <= 0)
        goto err_out_close_sockfd;

    rtn = sendMeasurement_udp(sockfd_data, buffer, header_size, clientInfo, stats);
    if(rtn <= 0) {
        DEBUG_MSG("Failed at sendMeasurement");
        goto err_out_close_sockfd;
    }
   
    close(sockfd_data);
    return SUCCESS;   

err_out_close_sockfd:
    close(sockfd_data);
err_out:
    return FAILURE;
} // end function runActiveBandwidthTest()


int runActiveBandwidthTest(struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    int sockfd = -1;
    int rtn;
    const int header_size = sizeof(struct tunhdr) + sizeof(struct bw_hdr);

    sockfd = openBandwidthSocket(clientInfo, stats->device);
    if(sockfd == -1) {
        return FAILURE;
    }
    
    unsigned int max_burst;
    rtn = receiveCts(sockfd, clientInfo->timeout, &max_burst);
        DEBUG_MSG("receiveCts:%d",receiveCts);
    if(rtn == FAILURE) {
        close(sockfd);
        return FAILURE;
    }

    // Never exceed the maximum size the server gave us.
    unsigned int burst_size = MIN(clientInfo->numBytes, max_burst);

    // The burst needs to fit the header at least.  If this check fails,
    // someone made a silly mistake somewhere.
    assert(burst_size >= header_size);

    char* buffer = (char*)malloc(burst_size);
    if(!buffer) {
        DEBUG_MSG("malloc failed");
        close(sockfd);
        return FAILURE;
    }
    fillBufferRandom(buffer, burst_size);

    if(sendBurst(sockfd, buffer, burst_size, clientInfo, stats) <= 0) {
        goto failure;
    }

    if(receiveBurst(sockfd, buffer, burst_size, clientInfo, stats) <= 0) {
        goto failure;
    }

    if(sendMeasurement(sockfd, buffer, burst_size, clientInfo, stats) <= 0) {
        goto failure;
    }
   
    free(buffer);
    close(sockfd);

    return SUCCESS;   

failure:
    free(buffer);
    close(sockfd);

    return FAILURE;
} // end function runActiveBandwidthTest()

/*
 * O P E N   B A N D W I D T H   S O C K E T
 *
 * Opens a TCP socket and connects to the bandwidth test server
 * that runs on the controller.
 *
 * Returns a connected socket or -1 on failure.
 */
static int openBandwidthSocket(struct bw_client_info* clientInfo, const char* bindDevice)
{
    int sockfd = -1;
    int rtn;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        ERROR_MSG("failed to open bandwidth socket");
        return -1;
    }

    rtn = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, bindDevice, IFNAMSIZ);
    if(rtn < 0) {
        ERROR_MSG("failed to bind socket to device");
        goto failure;
    }
    
    const int yes = 1;
    rtn = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if(rtn < 0) {
        ERROR_MSG("setsockopt SO_REUSEADDR failed");
        goto failure;
    }

    struct timeval timeout;
    set_timeval_us(&timeout, clientInfo->timeout);

    // Set socket timeout so that recv() cannot block indefinitely.
    rtn = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if(rtn < 0) {
        ERROR_MSG("setsockopt SO_RCVTIMEO failed (bad, but not critical)");
    }

    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family       = AF_INET;
    remoteAddr.sin_port         = htons(clientInfo->remote_port);
    remoteAddr.sin_addr.s_addr  = clientInfo->remote_addr;

    struct timespec connTimeout;
    connTimeout.tv_sec  = timeout.tv_sec;
    connTimeout.tv_nsec = timeout.tv_usec * 1000;

    rtn = connect_timeout(sockfd, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr), &connTimeout);
    if(rtn < 0) {
        if(errno == EWOULDBLOCK) {
            DEBUG_MSG("Bandwidth connection timed out.");
        } else {
            ERROR_MSG("Bandwidth connection failed");
        }
        goto failure;
    }
    
    return sockfd;

failure:
    close(sockfd);
    return -1;
}


static int openBandwidthSocket_udp(struct bw_client_info* clientInfo, const char* bindDevice)
{
    int sockfd = -1;
    int rtn;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0) {
        ERROR_MSG("failed to open bandwidth socket");
        return -1;
    }

    rtn = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, bindDevice, IFNAMSIZ);
    if(rtn < 0) {
        ERROR_MSG("failed to bind socket to device");
        goto failure;
    }
    
    const int yes = 1;
    rtn = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if(rtn < 0) {
        ERROR_MSG("setsockopt SO_REUSEADDR failed");
        goto failure;
    }

    struct timeval timeout;
    set_timeval_us(&timeout, clientInfo->timeout);

    // Set socket timeout so that recv() cannot block indefinitely.
    rtn = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if(rtn < 0) {
        ERROR_MSG("setsockopt SO_RCVTIMEO failed (bad, but not critical)");
    }
/*
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family       = AF_INET;
    remoteAddr.sin_port         = htons(clientInfo->remote_port);
    remoteAddr.sin_addr.s_addr  = clientInfo->remote_addr;

    struct timespec connTimeout;
    connTimeout.tv_sec  = timeout.tv_sec;
    connTimeout.tv_nsec = timeout.tv_usec * 1000;

    
rtn = connect_timeout(sockfd, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr), &connTimeout);
    if(rtn < 0) {
        if(errno == EWOULDBLOCK) {
            DEBUG_MSG("Bandwidth connection timed out.");
        } else {
            ERROR_MSG("Bandwidth connection failed");
        }
        goto failure;
    }
*/
    
    return sockfd;

failure:
    close(sockfd);
    return -1;
}



/*
 * RECEIVE CTS
 *
 * Waits up to timeout microseconds for a CTS packet.  If this returns SUCCESS,
 * then you are clear to flood the server with useless data.  If max_burst is
 * not null, this will write the server's max burst size into it.  If you try
 * to send more than that the server will ignore you.
 */
static int receiveCts(int sockfd, int timeout, unsigned int* max_burst)
{
    const int packet_size = sizeof(struct bw_hdr);
    char buffer[packet_size];
    int result;

    struct timespec tspec;
    tspec.tv_sec  = timeout / 1000000;
    tspec.tv_nsec = (timeout % 1000000) * 1000;

    result = recv_timeout(sockfd, buffer, packet_size, MSG_WAITALL, &tspec, 0);
    if(result < packet_size) {
        if(result == -1 && errno == EWOULDBLOCK) {
            DEBUG_MSG("Timed out receiving CTS");
        }
        return FAILURE;
    }
    
    struct bw_hdr* bw_hdr = (struct bw_hdr*)buffer;
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


/*
 * RECEIVE CTS
 *
 * Waits up to timeout microseconds for a CTS packet.  If this returns SUCCESS,
 * then you are clear to flood the server with useless data.  If max_burst is
 * not null, this will write the server's max burst size into it.  If you try
 * to send more than that the server will ignore you.
 */
static int receiveCts_udp(int sockfd, int timeout, unsigned int* max_burst)
{
    const int packet_size = sizeof(struct bw_hdr);
    char buffer[packet_size];
    int result;

    struct timespec tspec;
    tspec.tv_sec  = timeout / 1000000;
    tspec.tv_nsec = (timeout % 1000000) * 1000;

    result = recvfrom_timeout(sockfd, buffer, packet_size, MSG_WAITALL, &tspec, 0);
    if(result < packet_size) {
        if(result == -1 && errno == EWOULDBLOCK) {
            DEBUG_MSG("Timed out receiving CTS");
        }
        return FAILURE;
    }
    
    struct bw_hdr* bw_hdr = (struct bw_hdr*)buffer;
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


static int sendBurst(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    struct tunhdr* __restrict__ tun_hdr = (struct tunhdr*)buffer;
    struct bw_hdr* __restrict__ bw_hdr  = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));

    tun_hdr->seq_no     = htonl(SPECIAL_PKT_SEQ_NO);
    // We do not want to use TCP for latency estimation because of the
    // possibility for overestimation due to retransmission.
    tun_hdr->send_ts    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->recv_ts    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->service    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->prev_len   = 0;
    tun_hdr->node_id    = htons(getNodeID());
    tun_hdr->link_id    = htons(stats->link_id);
    tun_hdr->local_seq_no = htons(++clientInfo->local_seq_no);

    bw_hdr->type = htons(SPKT_ACTBW_BURST);
    bw_hdr->size = htonl(len);
    bw_hdr->bandwidth = 0.0; //bandwidth not known yet

    return send(sockfd, buffer, len, 0);
}

static int sendBurst_udp(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    int i, rtn;
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family       = AF_INET;
    remoteAddr.sin_port         = htons(clientInfo->remote_port);
    remoteAddr.sin_addr.s_addr  = clientInfo->remote_addr;

    for (i=0; i<=BW_UDP_PKTS; i++){
        //buffer += i*DEFAULT_MTU ;
        struct tunhdr* __restrict__ tun_hdr = (struct tunhdr*)buffer;
        struct bw_hdr* __restrict__ bw_hdr  = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));

        tun_hdr->seq_no     = htonl(SPECIAL_PKT_SEQ_NO);
        // We do not want to use TCP for latency estimation because of the
        // possibility for overestimation due to retransmission.
        tun_hdr->send_ts    = TUNHDR_NO_TIMESTAMP;
        tun_hdr->recv_ts    = TUNHDR_NO_TIMESTAMP;
        tun_hdr->service    = TUNHDR_NO_TIMESTAMP;
        tun_hdr->prev_len   = 0;
        tun_hdr->node_id    = htons(getNodeID());
        tun_hdr->link_id    = htons(stats->link_id);
        tun_hdr->local_seq_no = htons(++clientInfo->local_seq_no);

        bw_hdr->type = htons(SPKT_ACTBW_BURST);
        bw_hdr->size = htonl(len);
        bw_hdr->bandwidth = i; //bandwidth not known yet


        rtn = sendto(sockfd, buffer, DEFAULT_MTU, 0, (struct sockaddr*)&remoteAddr, sizeof(struct sockaddr));
        //DEBUG_MSG("sendBurst, %d, %d", i, rtn);
        //usleep(BW_UDP_SLEEP);
    }

    return rtn;
}

    
static int receiveBurst(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    //struct tunhdr* __restrict__ tun_hdr = (struct tunhdr*)buffer;
    struct bw_hdr* __restrict__ bw_hdr  = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));

    int result;
    struct timeval recvTime;

    struct timespec timeout;
    timeout.tv_sec  = clientInfo->timeout / 1000000;
    timeout.tv_nsec = (clientInfo->timeout % 1000000) * 1000;

    result = recv_timeout(sockfd, buffer, len, MSG_WAITALL, &timeout, &recvTime);
    if(result < len) {
        if(result == -1 && errno == EWOULDBLOCK) {
            DEBUG_MSG("Timed out receiving burst");
        }
        return FAILURE;
    }

    int elapsed_us = (recvTime.tv_sec * 1000000) + recvTime.tv_usec;
    unsigned numBits = getTransferSizeBits(len);
    stats->downlink_bw = (double)numBits / elapsed_us; //in mbps

    // The server measured its own downlink bandwidth and sent it to us
    stats->uplink_bw = 2*bw_hdr->bandwidth;

    return result;
}


static int receiveBurst_udp(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    struct bw_hdr *bw_hdr  = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));

    int flag=0, result=0;
    int bytesRcvd = 0;
    struct timeval recvTime;

    fd_set readSet;
    sigset_t sigset;

    FD_ZERO(&readSet);
    FD_SET(sockfd, &readSet);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);

    struct timeval  startTime, endTime;
    gettimeofday(&startTime, 0);
    gettimeofday(&endTime, 0);
    timeval_diff(&recvTime, &startTime, &endTime);

    struct timespec timeout;
    timeout.tv_sec  = clientInfo->timeout / 1000000;
    timeout.tv_nsec = (clientInfo->timeout % 1000000) * 1000;
    
    while(1){
        result = pselect(sockfd + 1, &readSet, 0, 0, &timeout, &sigset);
        //DEBUG_MSG("pselect:%d",result);
        if(result < 0) {
            break;
        } else if(!FD_ISSET(sockfd, &readSet)) {
            // Receive timed out
            errno = EWOULDBLOCK;
            break;
        }

        struct timeval  prevRecvTimeout;
        struct timeval  tempRecvTimeout = {
            .tv_sec     = timeout.tv_sec,
            .tv_usec    = timeout.tv_nsec / 1000,
        };

        //TODO: Check return values of {get,set}sockopt()
        socklen_t       timeoutSize = sizeof(prevRecvTimeout);
        getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, &timeoutSize);
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tempRecvTimeout, sizeof(tempRecvTimeout));



        result= recvfrom(sockfd, buffer, DEFAULT_MTU, MSG_WAITALL, NULL, 0);
        //DEBUG_MSG("Rcvd %d bytes", result);

        //buffer += result;

        if (!flag){
            flag=1;
            gettimeofday(&startTime, 0);
        }
        else{
            bytesRcvd += result;
        }

        gettimeofday(&endTime, 0);
        timeval_diff(&recvTime, &startTime, &endTime);

        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &prevRecvTimeout, sizeof(prevRecvTimeout));
    }

    int elapsed_us = (recvTime.tv_sec * 1000000) + recvTime.tv_usec;
    if (elapsed_us) {
        unsigned numBits = bytesRcvd*8; //getTransferSizeBits(len);
        stats->downlink_bw = (double)numBits / elapsed_us; //in mbps
        DEBUG_MSG("downlink_bw %f, Rcvd bytes:%d, Transfer time:%d",stats->downlink_bw, bytesRcvd, elapsed_us);
        // The server measured its own downlink bandwidth and sent it to us
        stats->uplink_bw = 1.5*bw_hdr->bandwidth;
    }

    return bytesRcvd;
}


static int sendMeasurement(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    struct tunhdr* __restrict__ tun_hdr = (struct tunhdr*)buffer;
    struct bw_hdr* __restrict__ bw_hdr  = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));
    const unsigned header_len = sizeof(struct tunhdr) + sizeof(struct bw_hdr);

    tun_hdr->seq_no = htonl(SPECIAL_PKT_SEQ_NO);
    // We do not want to use TCP for latency estimation because of the
    // possibility for overestimation due to retransmission.
    tun_hdr->send_ts    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->recv_ts    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->service    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->prev_len   = 0;
    tun_hdr->node_id = htons(getNodeID());
    tun_hdr->link_id = htons(stats->link_id);
    tun_hdr->local_seq_no = htons(clientInfo->local_seq_no);

    bw_hdr->type = htons(SPKT_ACTBW_BURST);
    bw_hdr->size = htonl(header_len);
    bw_hdr->bandwidth = stats->downlink_bw;
    
    return send(sockfd, buffer, header_len, 0);
}

static int sendMeasurement_udp(int sockfd, char* buffer, unsigned len, struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    struct tunhdr* __restrict__ tun_hdr = (struct tunhdr*)buffer;
    struct bw_hdr* __restrict__ bw_hdr  = (struct bw_hdr*)(buffer + sizeof(struct tunhdr));
    const unsigned header_len = sizeof(struct tunhdr) + sizeof(struct bw_hdr);

    tun_hdr->seq_no = htonl(SPECIAL_PKT_SEQ_NO);
    // We do not want to use TCP for latency estimation because of the
    // possibility for overestimation due to retransmission.
    tun_hdr->send_ts    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->recv_ts    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->service    = TUNHDR_NO_TIMESTAMP;
    tun_hdr->prev_len   = 0;
    tun_hdr->node_id = htons(getNodeID());
    tun_hdr->link_id = htons(stats->link_id);
    tun_hdr->local_seq_no = htons(clientInfo->local_seq_no);

    bw_hdr->type = htons(SPKT_ACTBW_BURST);
    bw_hdr->size = htonl(header_len);
    bw_hdr->bandwidth = stats->downlink_bw;
    
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family       = AF_INET;
    remoteAddr.sin_port         = htons(clientInfo->remote_port);
    remoteAddr.sin_addr.s_addr  = clientInfo->remote_addr;

    return sendto(sockfd, buffer, header_len, 0,(struct sockaddr*)&remoteAddr, sizeof(struct sockaddr));
}


/*
 * GET TRANSFER SIZE BITS
 *
 * Estimates the number of bits in sending the payload over TCP.  Assumes a
 * default MTU to calculate how many bits are transmitted for IP and TCP
 * headers.
 */
static unsigned int getTransferSizeBits(unsigned int payloadBytes)
{
    const int payloadMtu = DEFAULT_MTU - DEFAULT_IP_H_SIZE - DEFAULT_TCP_H_SIZE;
    unsigned int numPackets = (unsigned int)ceil((double)payloadBytes / payloadMtu);
    unsigned int numBytes = payloadBytes + 
        (DEFAULT_IP_H_SIZE + DEFAULT_TCP_H_SIZE) * numPackets;
    return numBytes * 8;
}

// vim: set et ts=4 sw=4:

