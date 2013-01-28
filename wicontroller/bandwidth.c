#define _BSD_SOURCE

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bandwidth.h"
#include "config.h"
#include "configuration.h"
#include "constants.h"
#include "database.h"
#include "debug.h"
#include "gateway.h"
#include "interface.h"
#include "kernel.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"

static void *bandwidth_server_func_udp(void *serverInfo);

int start_bandwidth_server_thread(struct bw_server_info *serverInfo)
{
    assert(serverInfo);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    // initialize private fields of the structure
    serverInfo->session_table = NULL;
    serverInfo->active_sessions = 0;

    int rtn = pthread_create(&serverInfo->udp_thread, &attr, 
            bandwidth_server_func_udp, serverInfo);
    if(rtn != 0) {
        ERROR_MSG("failed to create bandwidth thread");
        return -1;
    }

    pthread_attr_destroy(&attr);

    return 0;
}

/*
 * Called when we are done receiving a burst from a client.  Calculates the
 * uplink bandwidth and initiates the downlink burst.
 */
static int finish_recv_burst(struct bw_server_info *server, struct bw_session *session)
{
    long elapsed_us = timeval_diff(&session->last_packet_time, 
            &session->first_packet_time);

    session->measured_bw = (double)(session->bytes_recvd * 8) /
        (double)elapsed_us; //in Mbps

    DEBUG_MSG("bytes: %d, time: %ld, uplink_bw: %f Mbps",
            session->bytes_recvd, elapsed_us, session->measured_bw);

    int bytes_sent = session_send_burst(session, server->sockfd);
    if(bytes_sent > 0) {
        session->bytes_sent += bytes_sent;
    }

    gettimeofday(&session->timeout_time, NULL);
    timeval_add_us(&session->timeout_time, 
            server->start_timeout + session->remote_timeout);

    // If session times out at this point, terminate it.
    session->timeout_triggers_burst = 0;

    return bytes_sent;
}

/*
 * Remove any sessions from the table that have timed out.  Returns the minimum
 * positive time (in microseconds) until the next timeout or LONG_MAX if there
 * are no sessions.  This time can be safely used 
 */
static long timeout_sessions(struct bw_server_info *server)
{
    struct bw_session *session = NULL;
    struct bw_session *tmp_session = NULL;

    struct timeval now;
    gettimeofday(&now, NULL);

    long min_timeout = LONG_MAX;

    HASH_ITER(hh, server->session_table, session, tmp_session) {
        long diff = timeval_diff(&session->timeout_time, &now);
        if(diff <= 0) {
            if(session->timeout_triggers_burst) {
                finish_recv_burst(server, session);
            } else {
                HASH_DEL(server->session_table, session);
                free(session);

                if(server->active_sessions > 0)
                    server->active_sessions--;
                else
                    DEBUG_MSG("Warning: count of active sessions is not correct");
            }
        } else if(diff < min_timeout) {
            if(diff < min_timeout)
                min_timeout = diff;
        }
    }

    return min_timeout;
}

static int handle_rts_packet(struct bw_server_info *server, struct bw_session *session, 
        int sockfd, char *buffer, int buffer_len)
{
    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

    unsigned remote_mtu = ntohl(bw_hdr->mtu);
    if(remote_mtu < session->mtu)
        session->mtu = remote_mtu;

    session->remote_timeout = ntohl(bw_hdr->timeout);

    int result = session_send_cts(session, sockfd);
    if(result < 0) {
        DEBUG_MSG("session_send_cts failed");
        return -1;
    }

    gettimeofday(&session->timeout_time, NULL);
    timeval_add_us(&session->timeout_time, server->start_timeout);

    // If session times out at this point, terminate it.
    session->timeout_triggers_burst = 0;

    return 0;
}

static int handle_burst_packet(struct bw_server_info *server, struct bw_session *session,
        int sockfd, char *buffer, int buffer_len)
{
    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

    if(session->packets_recvd == 0) {
        get_recv_timestamp(sockfd, &session->first_packet_time);

        memcpy(&session->timeout_time, &session->first_packet_time, 
                sizeof(session->timeout_time));
        timeval_add_us(&session->timeout_time, server->data_timeout);

        // If session times out at this point, then start sending downlink
        // burst rather than terminate the session.
        session->timeout_triggers_burst = 1;
    }
    
    get_recv_timestamp(sockfd, &session->last_packet_time);

    session->packets_recvd++;
    session->bytes_recvd += buffer_len;

    if(bw_hdr->remaining == 0) {
        return finish_recv_burst(server, session);
    }

    return 0;
}

static int handle_stats_packet(struct bw_server_info *server, struct bw_session *session,
        int sockfd, char *buffer, int buffer_len)
{
    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

    // This is the bandwidth from the controller to the gateway
    double gw_downlink_bw = bw_hdr->bandwidth;

    DEBUG_MSG("Bandwidth for node %d link %d down %f Mbps, up: %f Mbps, bytes recvd: %d, bytes sent: %d",
            session->key.node_id, session->key.link_id, 
            gw_downlink_bw, session->measured_bw, 
            session->bytes_recvd, session->bytes_sent);

    struct gateway *gw = lookup_gateway_by_id(session->key.node_id);
    if(gw) {
        time(&gw->last_bw_time);
            
        struct interface *ife = find_interface_by_index(gw->head_interface, 
                session->key.link_id);
        if(ife) {
            if(gw_downlink_bw > 0) {
                long bps;

                if(gw_downlink_bw < (LONG_MAX / 1000000))
                    bps = (long)round(1000000.0 * gw_downlink_bw);
                else
                    bps = LONG_MAX;

                ife->meas_bw = bps;
                ife->meas_bw_time = time(NULL);

                virt_remote_bandwidth_hint(ife->public_ip.s_addr, bps);
            }

#ifdef WITH_DATABASE
            ife->avg_downlink_bw = ewma_update(ife->avg_downlink_bw, gw_downlink_bw, BW_EWMA_WEIGHT);
            ife->avg_uplink_bw = ewma_update(ife->avg_uplink_bw, session->measured_bw, BW_EWMA_WEIGHT);

            db_update_bandwidth(gw, ife, BW_UDP, gw_downlink_bw, session->measured_bw);
            db_update_link(gw, ife);
#endif
        }
    }

    return 0;
}

void *bandwidth_server_func_udp(void *serverInfo)
{
    struct bw_server_info* info = (struct bw_server_info*)serverInfo;

    info->sockfd = udp_bind_open(info->port, 0);
    if(info->sockfd < 0) {
        DEBUG_MSG("open_bandwidth_server_socket_udp: %d", info->sockfd);
        return 0;
    }

    char buffer[MTU];

    while(1) {
        long timeout_us = timeout_sessions(info);

        struct timeval timeout;
        set_timeval_us(&timeout, timeout_us);
    
        struct bw_session_key key;
        memset(&key, 0, sizeof(key));
        key.addr_len = sizeof(key.addr);

        int bytes_recvd = recvfrom_timeout(info->sockfd, buffer, sizeof(buffer), 0,
                (struct sockaddr *)&key.addr, &key.addr_len, &timeout);
        if(bytes_recvd >= sizeof(struct bw_hdr)) {
            struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;
            key.node_id = ntohs(bw_hdr->node_id);
            key.link_id = ntohs(bw_hdr->link_id);
            key.session_id = ntohs(bw_hdr->session_id);

            struct bw_session *session = NULL;
            HASH_FIND(hh, info->session_table, &key, sizeof(key), session);

            if(session && bw_hdr->type == BW_TYPE_RTS) {
                DEBUG_MSG("Warning: RTS received for active session");
                continue;
            } else if(!session && bw_hdr->type != BW_TYPE_RTS) {
                DEBUG_MSG("Warning: non-RTS packet received for unknown session");
                continue;
            }

            switch(bw_hdr->type) {
                case BW_TYPE_RTS:
                    if(info->active_sessions >= info->max_sessions) {
                        DEBUG_MSG("Client rejected due to session limit (%u)", 
                                info->max_sessions);
                        break;
                    }

                    session = malloc(sizeof(struct bw_session));
                    if(!session) {
                        DEBUG_MSG("out of memory");
                        break;
                    }
                    memcpy(&session->key, &key, sizeof(session->key));
                    session->mtu = get_mtu();
                    session->local_timeout = info->data_timeout;

                    handle_rts_packet(info, session, info->sockfd, buffer, bytes_recvd);

                    HASH_ADD(hh, info->session_table, key,
                            sizeof(struct bw_session_key), session);
                    info->active_sessions++;
                    break;

                case BW_TYPE_BURST:
                    handle_burst_packet(info, session, info->sockfd, buffer, bytes_recvd);
                    break;

                case BW_TYPE_STATS:
                    handle_stats_packet(info, session, info->sockfd, buffer, bytes_recvd);
                    break;

                default:
                    break;
            }
        }
    }

    close(info->sockfd);
    return 0;
}


