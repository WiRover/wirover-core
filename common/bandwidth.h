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

/* Storage for a queue of waiting bandwidth clients. */
struct bw_client {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int pkt_len;

    double uplink_bw;

    struct timeval rts_time;

    struct bw_client *next;
};

struct bw_server_info {
    // Settings for the bandwidth thread
    // Set these values before calling startBandwidthServerThread()
    unsigned int       timeout; //in microseconds
    unsigned short     port;

    pthread_t          tcp_thread;
    pthread_t          udp_thread;

    struct bw_client   *clients_head;
    struct bw_client   *clients_tail;
};

struct bw_client_info {
    // Settings for the bandwidth thread
    // Set these values before calling startBandwidthClientThread()
    unsigned int       timeout; //in microseconds
    unsigned int       remote_addr;
    unsigned short     remote_port;
    unsigned int       interval; //in microseconds

    pthread_t          thread;
    bw_callback_t      callback;
    unsigned short     local_seq_no;

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
    uint32_t size;
    double   bandwidth;

    uint16_t node_id;
    uint16_t link_id;
} __attribute__((__packed__));

int     start_bandwidth_server_thread(struct bw_server_info *serverInfo);

int     start_bandwidth_client_thread(struct bw_client_info *clientInfo);
void    registerBandwidthCallback(struct bw_client_info* clientInfo, bw_callback_t callback);
void    setBandwidthInterval(struct bw_client_info* clientInfo, unsigned int interval);

void    pauseBandwidthThread(struct bw_client_info* clientInfo);
void    resumeBandwidthThread(struct bw_client_info* clientInfo);

#endif //_BANDWIDTH_H_

