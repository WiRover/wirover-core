#define _BSD_SOURCE

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
#include <limits.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "arguments.h"
#include "bandwidth.h"
#include "config.h"
#include "configuration.h"
#include "contchan.h"
#include "debug.h"
#include "interface.h"
#include "kernel.h"
#include "netlink.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"

// Internal functions
void*   bandwidthThreadFunc(void* clientInfo);
int     runActiveBandwidthTest(struct bw_client_info* clientInfo, struct bw_stats* stats);
int     runActiveBandwidthTest_udp(struct bw_client_info* clientInfo, struct bw_stats* stats);

static int openBandwidthSocket_udp(struct bw_client_info* clientInfo, const char* bindDevice);
static int receiveCts_udp(int sockfd, int timeout, struct bw_hdr *dest_hdr);
static int recv_burst_udp(struct bw_client_info *client, struct bw_stats *stats,
        int sockfd, char *buffer, int buffer_len, unsigned server_timeout);


/*
 * Starts a thread that will continually run bandwidth tests.  
 *
 * The caller must pass a pointer to a bw_client_info structure that has the
 * settings fields properly set.
 *
 * Returns SUCCESS or FAILURE.
 */
int start_bandwidth_client_thread(struct bw_client_info* clientInfo)
{
    assert(clientInfo != 0);
    
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

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
 * Sets the interval for bandwidth tests.  The interval should be in seconds.
 */
void setBandwidthInterval(struct bw_client_info* clientInfo, unsigned int interval)
{
    assert(clientInfo != 0);
    clientInfo->interval = interval;
}

/*
 * Pauses execution of the active bandwidth tests until resumeBandwidthThread()
 * is called.
 */
void pauseBandwidthThread(struct bw_client_info* clientInfo)
{
    clientInfo->pauseFlag = 1;
}

/*
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

void* bandwidthThreadFunc(void* clientInfo)
{
    struct bw_client_info* info = (struct bw_client_info*)clientInfo;

    while(1) {
        // Put the thread to sleep if we want to pause active bandwidth measurements
        if(info->pauseFlag) {
            pthread_mutex_lock(&info->pauseMutex);
            while(info->pauseFlag) {
                pthread_cond_wait(&info->pauseCond, &info->pauseMutex);
            }
            pthread_mutex_unlock(&info->pauseMutex);
        }

        /* It may seem inefficient to copy the interface list before doing the
         * bandwidth tests, but this is done to minimize the time spent in the
         * critical section of the lock.  The bandwidth tests make take a long
         * time (several seconds or more).  Locking the interface list for that
         * long will delay the gateway's response to added or removed
         * interfaces. */
        obtain_read_lock(&interface_list_lock);
        struct interface_copy *active_list = NULL;
        int num_active = copy_active_interfaces(interface_list, &active_list);
        release_read_lock(&interface_list_lock);

        int j;
        for(j = 0; j < num_active; j++) {
            struct bw_stats stats;
            memcpy(stats.device, active_list[j].name, IFNAMSIZ);
            stats.link_id = active_list[j].index;
            stats.downlink_bw = NAN;
            stats.uplink_bw = NAN;
            
            int rtn = FAILURE;

            if(BW_TYPE == BW_TCP) {
                DEBUG_MSG("BW_TCP not supported");
                //rtn = runActiveBandwidthTest(info, &stats);
            } else if(BW_TYPE == BW_UDP) {
                rtn = runActiveBandwidthTest_udp(info, &stats);
                if(rtn == FAILURE)
                    DEBUG_MSG("Bandwidth test on %s failed", active_list[j].name);
            } else {
                DEBUG_MSG("BW_TYPE not defined");
            }

            if(rtn == SUCCESS && info->callback != 0) {
                obtain_read_lock(&interface_list_lock);
                struct interface *ife;
                ife = find_interface_by_index(interface_list, active_list[j].index);
                if(ife) {
                    info->callback(clientInfo, ife, &stats);
                }
                release_read_lock(&interface_list_lock);
            }

            // Give some time for the connection to be torn down and
            // perhaps for other gateways to access the server.
            safe_usleep(ACTIVE_BW_DELAY);
        }

        if(active_list) {
            free(active_list);
        }

        sleep(info->interval);
    }

    return 0;
}

/*
 * Runs a bandwidth test by transferring a random file (a large, contiguous
 * block of data).  This consists of opening a TCP connection, sending the
 * data, then receiving the same data again.
 *
 * Returns SUCCESS or FAILURE.  SUCCESS is returned only if the entire test is
 * completed and the uplink and downlink measurements are available.
 */
int runActiveBandwidthTest_udp(struct bw_client_info* clientInfo, struct bw_stats* stats)
{
    int sockfd_data = -1;
    int rtn;
    char buffer[MTU];

    sockfd_data = openBandwidthSocket_udp(clientInfo, stats->device);
    if(sockfd_data == -1){
        DEBUG_MSG("sockfd_data: %d", sockfd_data); 
        return FAILURE;
    }

    struct bw_session session;
    memset(&session, 0, sizeof(session));
   
    struct sockaddr_in *remoteAddr = (struct sockaddr_in *)&session.key.addr;
    remoteAddr->sin_family       = AF_INET;
    remoteAddr->sin_port         = htons(clientInfo->remote_port);
    remoteAddr->sin_addr.s_addr  = clientInfo->remote_addr;
    session.key.addr_len = sizeof(struct sockaddr_in);

    session.key.node_id = get_unique_id();
    session.key.link_id = stats->link_id;
    session.key.session_id = clientInfo->next_session_id++;

    session.mtu = get_mtu();
    session.local_timeout = clientInfo->data_timeout;

    rtn = session_send_rts(&session, sockfd_data);
    if(rtn < 0) {
        ERROR_MSG("Sending RTS failed");
        goto failure;
    }

    // Wait for CTS
    struct bw_hdr cts_hdr;
    rtn = receiveCts_udp(sockfd_data, clientInfo->start_timeout, &cts_hdr);
    if(rtn == FAILURE) {
        goto failure;
    }

    session.remote_timeout = ntohl(cts_hdr.timeout);

    unsigned remote_mtu = ntohl(cts_hdr.mtu);
    if(remote_mtu < session.mtu)
        session.mtu = remote_mtu;

    // The burst needs to fit the header at least.  If this check fails,
    // someone made a silly mistake somewhere.
    if(session.mtu < sizeof(struct bw_hdr)) {
        DEBUG_MSG("Warning: the MTU (%u) is too small (need at least %u)",
                session.mtu, sizeof(struct bw_hdr));
        goto failure;
    }

    rtn = session_send_burst(&session, sockfd_data);
    if (rtn < 0) {
        goto failure;
    } else {
        session.bytes_sent += rtn;
    }

    rtn = recv_burst_udp(clientInfo, stats, sockfd_data, buffer, sizeof(buffer), 
            session.remote_timeout);
    if (rtn <= 0) {
        DEBUG_MSG("recv_burst_udp: %d", rtn);
        goto failure;
    }

    session.measured_bw = stats->downlink_bw;

    rtn = session_send_stats(&session, sockfd_data);
    if(rtn <= 0) {
        DEBUG_MSG("Failed at sendMeasurement");
        goto failure;
    }
   
    close(sockfd_data);
    return SUCCESS;   

failure:
    close(sockfd_data);
    return FAILURE;
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
    set_timeval_us(&timeout, clientInfo->start_timeout);

    // Set socket timeout so that recv() cannot block indefinitely.
    rtn = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    if(rtn < 0) {
        ERROR_MSG("setsockopt SO_RCVTIMEO failed (bad, but not critical)");
    }
    
    return sockfd;

failure:
    close(sockfd);
    return -1;
}



/*
 * Waits up to timeout microseconds for a CTS packet.  If this returns SUCCESS,
 * then you are clear to flood the server with useless data.  If dest_hdr is
 * not null, this will write the received header into it.
 */
static int receiveCts_udp(int sockfd, int timeout, struct bw_hdr *dest_hdr)
{
    const int packet_size = sizeof(struct bw_hdr);
    char buffer[packet_size];
    int result;

    struct timeval timeout_tv;
    set_timeval_us(&timeout_tv, timeout);

    result = recvfrom_timeout(sockfd, buffer, packet_size, 0, 
            0, 0, &timeout_tv);
    if(result < packet_size) {
        if(result == -1 && errno == EWOULDBLOCK) {
            DEBUG_MSG("Timed out receiving CTS");
        }
        return FAILURE;
    }

    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

    if(bw_hdr->type != BW_TYPE_CTS) {
        DEBUG_MSG("Received something other than CTS... look into this");
        return FAILURE;
    }

    if(dest_hdr) {
        memcpy(dest_hdr, bw_hdr, sizeof(struct bw_hdr));
    }

    return SUCCESS;
}

static int recv_burst_udp(struct bw_client_info *client, struct bw_stats *stats,
        int sockfd, char *buffer, int buffer_len, unsigned server_timeout)
{
    int result;
    int bytes_recvd = 0;

    int is_first_pkt = 1;
    struct timeval first_pkt_time;
    struct timeval last_pkt_time;

    long remaining_us = server_timeout + client->start_timeout;
    while(remaining_us > 0) {
        struct timeval timeout;
        set_timeval_us(&timeout, remaining_us);

        struct timeval recvfrom_start;
        gettimeofday(&recvfrom_start, 0);

        struct sockaddr_storage sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);

        result = recvfrom_timeout(sockfd, buffer, buffer_len, 0,
                (struct sockaddr *)&sender_addr, &sender_addr_len, &timeout);
        if(result >= (int)sizeof(struct bw_hdr)) {
            struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

            // TODO: Verify sender address matches server
            if(bw_hdr->type == BW_TYPE_BURST) {
                if(is_first_pkt) {
                    get_recv_timestamp(sockfd, &first_pkt_time);
                    is_first_pkt = 0;
                    remaining_us = client->data_timeout;
                } else {
                    get_recv_timestamp(sockfd, &last_pkt_time);
                    bytes_recvd += result;
                }

                struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;
                stats->uplink_bw = bw_hdr->bandwidth;

                // If we receive the last packet that has remaining == 0, then we
                // do not need to wait for timeout.
                if(bw_hdr->remaining == 0) {
                    break;
                }
                
            }
        }

        remaining_us -= get_elapsed_us(&recvfrom_start);
    }

    long elapsed_us = timeval_diff(&last_pkt_time, &first_pkt_time);
    stats->downlink_bw = (double)(bytes_recvd * 8) / (double)elapsed_us; //in Mbps

    DEBUG_MSG("bytes: %d, time: %ld, downlink_bw: %f Mbps, uplink_bw: %f Mbps",
            bytes_recvd, elapsed_us, stats->downlink_bw, stats->uplink_bw);

    return bytes_recvd;
}

