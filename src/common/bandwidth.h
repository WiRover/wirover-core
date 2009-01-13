/*
 * The active bandwidth measurement works by sending a large burst of data and
 * measuring the time taken to receive it.  The protocol is described in detail
 * below.  For the purposes of this explanation, server=wicontroller and
 * client=wigateway.
 *
 * 1. The client opens a TCP connection to the server.  This will very possibly
 * complete before the server is ready to begin receiving data, such as when it
 * is busy with another client, so the client must wait on a blocking recv().
 *
 * 2. The server sends a small clear-to-send (CTS) message.  This will also
 * contain the maximum number of bytes the server is willing to receive.  The
 * client must observe this limit.
 *
 * 3. The client should immediately begin an uninterrupted burst of its chosen
 * size.  The size will be encoded in the burst header.
 *
 * 4. The server receives the burst and echoes it to the client along with a
 * calculated uplink bandwidth.
 *
 * 5. The client receives the burst and sends a small packet back to the server
 * with the calculated downlink bandwidth.
 *
 * 6. Both sides may tear down the connection.
 */

#ifndef _BANDWIDTH_H_
#define _BANDWIDTH_H_

#include <stdint.h>
#include <pthread.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "uthash.h"

enum {
    BW_UDP = 1,
    BW_TCP,
};

// Forward declarations of structures
struct interface;
struct bw_server_info;
struct bw_client_info;
struct bw_stats;
struct bw_test_payload;

// typedef for a callback function to get bw statistics
typedef void (*bw_callback_t)(struct bw_client_info *, struct interface *,
        struct bw_stats *);

#define BW_TYPE_RTS         0x01
#define BW_TYPE_CTS         0x02
#define BW_TYPE_BURST       0x03
#define BW_TYPE_STATS       0x04

struct bw_session_key {
    struct sockaddr_storage addr;
    socklen_t addr_len;

    unsigned short node_id;
    unsigned short link_id;
    unsigned short session_id;
};

struct bw_session {
    struct bw_session_key key;

    unsigned mtu;
    unsigned local_timeout;
    unsigned remote_timeout;
    double measured_bw;

    struct timeval timeout_time;
    int timeout_triggers_burst;

    long packets_recvd;
    long bytes_recvd;
    long bytes_sent;

    struct timeval first_packet_time;
    struct timeval last_packet_time;

    UT_hash_handle hh;
};

struct bw_server_info {
    // Settings for the bandwidth thread
    // Set these values before calling startBandwidthServerThread()
    unsigned int       start_timeout; //in microseconds
    unsigned int       data_timeout; //in microseconds
    unsigned short     port;
    unsigned int       max_sessions;

    pthread_t          tcp_thread;
    pthread_t          udp_thread;

    int sockfd;

    struct bw_session *session_table;
    int active_sessions;
};

struct bw_client_info {
    // Settings for the bandwidth thread
    // Set these values before calling startBandwidthClientThread()
    unsigned int       start_timeout; //in microseconds
    unsigned int       data_timeout; //in microseconds
    unsigned int       remote_addr;
    unsigned short     remote_port;
    unsigned int       interval; //in microseconds

    pthread_t          thread;
    bw_callback_t      callback;
    unsigned short     local_seq_no;

    unsigned short     next_session_id;

    int                pauseFlag;
    pthread_cond_t     pauseCond;
    pthread_mutex_t    pauseMutex;
};

struct bw_stats {
    char               device[IFNAMSIZ];
    unsigned short     link_id;

    double             downlink_bw;
    double             uplink_bw;
};

struct bw_hdr {
    uint8_t  type;
    uint32_t mtu;
    uint32_t timeout;
    double   bandwidth;

    uint16_t node_id;
    uint16_t link_id;

    uint16_t session_id;
    uint16_t remaining;
} __attribute__((__packed__));

int     start_bandwidth_server_thread(struct bw_server_info *serverInfo);

int     start_bandwidth_client_thread(struct bw_client_info *clientInfo);
void    registerBandwidthCallback(struct bw_client_info* clientInfo, bw_callback_t callback);
void    setBandwidthInterval(struct bw_client_info* clientInfo, unsigned int interval);

void    pauseBandwidthThread(struct bw_client_info* clientInfo);
void    resumeBandwidthThread(struct bw_client_info* clientInfo);

int session_send(const struct bw_session *session, int sockfd, int type);
int session_send_rts(const struct bw_session *session, int sockfd);
int session_send_cts(const struct bw_session *session, int sockfd);
int session_send_burst(const struct bw_session *session, int sockfd);
int session_send_stats(const struct bw_session *session, int sockfd);

#endif //_BANDWIDTH_H_

