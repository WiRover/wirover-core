/*
 * U D P   P I N G . H
 */

#ifndef _UDP_PING_H_
#define _UDP_PING_H_

#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <linux/if.h>

// Forward declarations for structures
struct link;
struct ping_stats;
struct ping_client_info;

typedef int (*ping_callback_t)(struct ping_client_info*, struct link*, struct ping_stats*);

struct ping_server_info {
    unsigned short  local_port;

    pthread_t       thread;
    int             sockfd;
};

struct ping_client_info {
    unsigned int    interval; //in microseconds
    unsigned int    timeout; //in microseconds

    pthread_t       thread;
    ping_callback_t callback;
};

struct gps_payload {
    uint8_t status;
    double  latitude;
    double  longitude;
    double  altitude;
    double  track;
    double  speed;
    double  climb;
} __attribute__((__packed__));

struct ping_pkt {
    uint16_t            type;
    struct gps_payload  gps;

    // Timestamp went sent from gateway
    int32_t             sent_time_sec;
    int32_t             sent_time_usec;
    struct timeval      rcvd_time;
} __attribute__((__packed__));

struct ping_stats_pkt {
    uint16_t type;
    int32_t  rtt;
} __attribute__((__packed__));

struct ping_stats {
    struct timeval  send_tv;
    struct timeval  recv_tv;
    int             rtt;
    int             t_ul;
    unsigned int    losses;
    unsigned int    consecutive_losses;
    unsigned short  local_seq_no;

    char            device[IFNAMSIZ];
    unsigned short  link_id;
};

#if defined(CONTROLLER)
int     startPingServerThread(struct ping_server_info* serverInfo);
#elif defined(GATEWAY)
int     startPingClientThread(struct ping_client_info* clientInfo);
void    registerPingCallback(struct ping_client_info* clientInfo, ping_callback_t func);
void    setUdpPingTarget(const struct sockaddr *dest, socklen_t dest_len);
int     sendPing(struct link *link);
#endif

#endif //_UDP_PING_H_

/* vim: set et ts=4 sw=4: */

