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
#include "database.h"
#include "debug.h"
#include "gateway.h"
#include "interface.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"

static void *bandwidth_server_func_udp(void *serverInfo);
static int wait_for_client_udp(struct bw_server_info *server, int sockfd, 
        char *buffer, int buffer_len);
static int handle_bandwidth_client_udp(struct bw_server_info *serverInfo, 
        struct bw_client *client, int sockfd, char *buffer, int buffer_len);
static int send_cts_udp(int sockfd, struct sockaddr *dest_addr, socklen_t dest_len);
static int recv_client_burst_udp(struct bw_server_info *server, struct bw_client *client,
        int sockfd, char *buffer, int buffer_len);
static int send_burst_udp(const struct bw_client *client, int sockfd, 
        char *buffer, int buffer_len);

int start_bandwidth_server_thread(struct bw_server_info *serverInfo)
{
    assert(serverInfo);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    // initialize private fields of the structure
    serverInfo->clients_head = 0;
    serverInfo->clients_tail = 0;

    int rtn = pthread_create(&serverInfo->udp_thread, &attr, 
            bandwidth_server_func_udp, serverInfo);
    if(rtn != 0) {
        ERROR_MSG("failed to create bandwidth thread");
        return -1;
    }

    pthread_attr_destroy(&attr);

    return 0;
}

void *bandwidth_server_func_udp(void *serverInfo)
{
    struct bw_server_info* info = (struct bw_server_info*)serverInfo;

    info->clients_head = 0;
    info->clients_tail = 0;

    int sockfd = udp_bind_open(info->port, 0);
    if(sockfd < 0) {
        DEBUG_MSG("open_bandwidth_server_socket_udp: %d", sockfd);
        return 0;
    }

    char buffer[MTU];

    while(1) {
        if(info->clients_head) {
            struct bw_client *client = info->clients_head;

            info->clients_head = info->clients_head->next;
            if(!info->clients_head)
                info->clients_tail = 0;

            handle_bandwidth_client_udp(info, client, sockfd, buffer, MTU);

            free(client);
        } else {
            wait_for_client_udp(info, sockfd, buffer, MTU);
        }
    }

    close(sockfd);
    return 0;
}

static int handle_bandwidth_client_udp(struct bw_server_info *serverInfo, 
        struct bw_client *client, int sockfd, char *buffer, int buffer_len)
{
    int result;
    int bytes_recvd = 0;

    result = send_cts_udp(sockfd, (struct sockaddr *)&client->addr, 
            client->addr_len);
    if(result != SUCCESS)
        return FAILURE;

    bytes_recvd = recv_client_burst_udp(serverInfo, client, sockfd, buffer, buffer_len);
    if(bytes_recvd <= 0)
        return FAILURE;

    //Send Packets for DL BW estimation by Client
    int bytes_sent = send_burst_udp(client, sockfd, buffer, buffer_len);
    if(bytes_sent <= 0)
        return FAILURE;

    // TODO: We should use whatever timeout the gateway is using.
    usleep(serverInfo->timeout);

    int recvd_last_pkt = 0;
    
    long remaining_us = serverInfo->timeout;
    while(remaining_us > 0) {
        struct timeval timeout;
        set_timeval_us(&timeout, remaining_us);

        struct timeval recvfrom_start;
        gettimeofday(&recvfrom_start, 0);

        struct sockaddr_storage his_addr;
        socklen_t his_addr_len = sizeof(his_addr);

        result = recvfrom_timeout(sockfd, buffer, buffer_len, 0, 
                (struct sockaddr *)&his_addr, &his_addr_len, &timeout);
        if(result > 0) {
            struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

            if(bw_hdr->type == BW_TYPE_STATS && his_addr_len == client->addr_len &&
                    memcmp(&his_addr, &client->addr, his_addr_len) == 0) {
                recvd_last_pkt = 1;
                break;
            } else if(bw_hdr->type == BW_TYPE_RTS) {
                // Received an RTS from a new client.
                struct bw_client *new_client = malloc(sizeof(struct bw_client));
                if(new_client) {
                    memcpy(&new_client->addr, &his_addr, his_addr_len);
                    new_client->addr_len = his_addr_len;
                    new_client->pkt_len = ntohl(bw_hdr->size);
                    get_recv_timestamp(sockfd, &new_client->rts_time);
                    new_client->uplink_bw = NAN; // not measured yet
                    new_client->next = 0;

                    if(serverInfo->clients_tail) {
                        serverInfo->clients_tail->next = new_client;
                        serverInfo->clients_tail = new_client;
                    } else {
                        serverInfo->clients_head = new_client;
                        serverInfo->clients_tail = new_client;
                    }
                }
            }
        }

        remaining_us -= get_elapsed_us(&recvfrom_start);
    }

    if(recvd_last_pkt) {
        struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

        unsigned short h_node_id = ntohs(bw_hdr->node_id);
        unsigned short h_link_id = ntohs(bw_hdr->link_id);

        // This is the bandwidth from the controller to the gateway
        double gw_downlink_bw = bw_hdr->bandwidth;

        DEBUG_MSG("Bandwidth for node %d link %d down %f Mbps, up: %f Mbps, bytes recvd: %d, sent: %d",
                h_node_id, h_link_id, gw_downlink_bw, client->uplink_bw, 
                bytes_recvd, bytes_sent);

        struct gateway *gw = lookup_gateway_by_id(h_node_id);
        if(gw) {
            time(&gw->last_bw_time);

#ifdef WITH_DATABASE
            struct interface *ife = find_interface_by_index(gw->head_interface, 
                    h_link_id);
            if(ife) {
                ife->avg_downlink_bw = ewma_update(ife->avg_downlink_bw, gw_downlink_bw, BW_EWMA_WEIGHT);
                ife->avg_uplink_bw = ewma_update(ife->avg_uplink_bw, client->uplink_bw, BW_EWMA_WEIGHT);

                db_update_bandwidth(gw, ife, BW_UDP, gw_downlink_bw, client->uplink_bw);
                db_update_link(gw, ife);
            }
#endif
        }
    }

    return SUCCESS;
}
            
static int wait_for_client_udp(struct bw_server_info *server, int sockfd, 
        char *buffer, int buffer_len)
{
    int result;
    
    struct sockaddr_storage his_addr;
    socklen_t his_addr_len = sizeof(his_addr);

    result = recvfrom(sockfd, buffer, buffer_len, 0,
            (struct sockaddr *)&his_addr, &his_addr_len);
    if(result >= (int)sizeof(struct bw_hdr)) {
        struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;

        if(bw_hdr->type == BW_TYPE_RTS) {
            // Received an RTS from a new client.
            struct bw_client *new_client = malloc(sizeof(struct bw_client));
            if(new_client) {
                memcpy(&new_client->addr, &his_addr, his_addr_len);
                new_client->addr_len = his_addr_len;
                new_client->pkt_len = ntohl(bw_hdr->size);
                get_recv_timestamp(sockfd, &new_client->rts_time);
                new_client->uplink_bw = NAN; // not measured yet
                new_client->next = 0;

                if(server->clients_tail) {
                    server->clients_tail->next = new_client;
                    server->clients_tail = new_client;
                } else {
                    server->clients_head = new_client;
                    server->clients_tail = new_client;
                }
            }
        }
    }

    return 0;
}

static int send_cts_udp(int sockfd, struct sockaddr *dest_addr, socklen_t dest_len)
{
    const int packet_size = sizeof(struct bw_hdr);
    char buffer[packet_size];
    memset(buffer, 0, sizeof(buffer));

    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;
    bw_hdr->type = BW_TYPE_CTS;
    bw_hdr->size = htonl(DEFAULT_MTU);
    bw_hdr->bandwidth = 0.0;

    int rtn = sendto(sockfd, buffer, packet_size, 0, dest_addr, dest_len);
    if(rtn < 0) {
        ERROR_MSG("Sending CTS failed");
        return FAILURE;
    } else if(rtn < packet_size) {
        DEBUG_MSG("Sending CTS stopped early");
        return FAILURE;
    }

    return SUCCESS;
}

static int recv_client_burst_udp(struct bw_server_info *server, struct bw_client *client, 
        int sockfd, char *buffer, int buffer_len)
{
    int result;
    int bytes_recvd = 0;

    int is_first_pkt = 1;
    struct timeval first_pkt_time;
    struct timeval last_pkt_time;

    long remaining_us = server->timeout;
    while(remaining_us > 0) {
        struct timeval timeout;
        set_timeval_us(&timeout, remaining_us);

        struct timeval recvfrom_start;
        gettimeofday(&recvfrom_start, 0);

        struct sockaddr_storage his_addr;
        socklen_t his_addr_len = sizeof(his_addr);

        result = recvfrom_timeout(sockfd, buffer, buffer_len, 0, 
                (struct sockaddr *)&his_addr, &his_addr_len, &timeout);
        if(result >= (int)sizeof(struct bw_hdr)) {
            struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;
            
            if(bw_hdr->type == BW_TYPE_BURST && his_addr_len == client->addr_len &&
                    memcmp(&his_addr, &client->addr, his_addr_len) == 0) {
                if(is_first_pkt) {
                    get_recv_timestamp(sockfd, &first_pkt_time);
                    is_first_pkt = 0;
                } else {
                    get_recv_timestamp(sockfd, &last_pkt_time);
                    bytes_recvd += result;
                }

                remaining_us = server->timeout;
            } else if(bw_hdr->type == BW_TYPE_RTS) {
                // Received an RTS from a new client.
                struct bw_client *new_client = malloc(sizeof(struct bw_client));
                if(new_client) {
                    memcpy(&new_client->addr, &his_addr, sizeof(his_addr));
                    new_client->addr_len = his_addr_len;
                    new_client->pkt_len = ntohl(bw_hdr->size);
                    get_recv_timestamp(sockfd, &new_client->rts_time);
                    new_client->uplink_bw = NAN; // not measured yet
                    new_client->next = 0;

                    if(server->clients_tail) {
                        server->clients_tail->next = new_client;
                        server->clients_tail = new_client;
                    } else {
                        server->clients_head = new_client;
                        server->clients_tail = new_client;
                    }
                }
            }
        }

        remaining_us -= get_elapsed_us(&recvfrom_start);
    }
    
    long elapsed_us = timeval_diff(&last_pkt_time, &first_pkt_time);
    double uplink_bw = (double)(bytes_recvd * 8) / (double)elapsed_us; //in Mbps

    client->uplink_bw = uplink_bw;

    DEBUG_MSG("bytes: %d, time: %ld, uplink_bw: %f Mbps",
            bytes_recvd, elapsed_us, uplink_bw);

    return bytes_recvd;
}

static int send_burst_udp(const struct bw_client *client, int sockfd, 
        char *buffer, int buffer_len)
{
    int i;
    int bytes_sent = 0;
    int result;
        
    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;
    bw_hdr->type = BW_TYPE_BURST;
    bw_hdr->bandwidth = client->uplink_bw;

    for(i = 0; i < BW_UDP_PKTS; i++) {
        result = sendto(sockfd, buffer, client->pkt_len, 0, 
                (struct sockaddr *)&client->addr, client->addr_len);
        if(result > 0)
            bytes_sent += result;
    }

    return bytes_sent;
}

