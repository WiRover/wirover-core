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

// Forward declarations of structures
struct link;
struct bw_server_info;
struct bw_client_info;
struct bw_stats;
struct bw_test_payload;

// typedef for a callback function to get bw statistics
typedef void (*bw_callback_t)(struct bw_client_info*, struct link*, struct bw_stats*);

enum {
    BW_UDP = 1,
    BW_TCP,
};

#define SPKT_ACTBW_CTS      0x10
#define SPKT_ACTBW_BURST    0x11
#define SPKT_ACTBW_STATS    0x12

struct bw_server_info {
    // Settings for the bandwidth thread
    // Set these values before calling startBandwidthServerThread()
    unsigned int       timeout; //in microseconds
    unsigned short     local_port;

    pthread_t          tcp_thread;
    pthread_t          udp_thread;
};

struct bw_client_info {
    // Settings for the bandwidth thread
    // Set these values before calling startBandwidthClientThread()
    unsigned int       timeout; //in microseconds
    unsigned int       numBytes;
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
    uint16_t        type;
    uint32_t        size;
    double          bandwidth;

    uint16_t        node_id;
    uint16_t        link_id;
} __attribute__((__packed__));

#ifdef CONTROLLER
int     startBandwidthServerThread(struct bw_server_info* serverInfo);
#endif

#ifdef GATEWAY
int     startBandwidthClientThread(struct bw_client_info* clientInfo);
void    registerBandwidthCallback(struct bw_client_info* clientInfo, bw_callback_t callback);
void    setBandwidthInterval(struct bw_client_info* clientInfo, unsigned int interval);

void    pauseBandwidthThread(struct bw_client_info* clientInfo);
void    resumeBandwidthThread(struct bw_client_info* clientInfo);
#endif

#endif //_BANDWIDTH_H_

