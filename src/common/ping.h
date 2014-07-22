#ifndef _PING_H_
#define _PING_H_

#include <stdint.h>
#include <sys/time.h>
#include <openssl/sha.h>

#define PING_INVALID            0x00
#define PING_REQUEST            0x10
#define PING_REQUEST_ERROR      0x20
#define PING_RESPONSE           0x30
#define PING_RESPONSE_ERROR     0x40
#define PING_SECOND_RESPONSE    0x50

#define PING_NO_PAYLOAD         0x00
#define PING_GPS_PAYLOAD        0x01
#define PING_PASSIVE_PAYLOAD    0x02

#define USEC_PER_SEC            1000000
#define PING_LOSS_THRESHOLD     4

#define PROC_NET_DEV            "/proc/net/dev"
#define PROC_NET_DEV_STAT_COLS  8

/* Ping error codes */
enum {
    PING_ERR_OK = 0,
    PING_ERR_TOO_SHORT,
    PING_ERR_BAD_NODE,
    PING_ERR_BAD_LINK,
    PING_ERR_BAD_HASH,
    PING_ERR_NOT_PING,
    PING_ERR_BAD_TYPE,
    MAX_PING_ERR,
};

struct ping_packet {
    uint8_t  type;
    uint32_t seq_no;
    int8_t   link_state;
    uint16_t src_id;
    uint32_t link_id;
    uint32_t sender_ts;
    uint32_t receiver_ts;
    uint8_t  digest[SHA256_DIGEST_LENGTH];
} __attribute__((__packed__));

struct gps_payload {
    uint8_t next;
    uint8_t status;
    double  latitude;
    double  longitude;
    double  altitude;
    double  track;
    double  speed;
    double  climb;
} __attribute__((__packed__));

struct passive_payload {
    uint8_t  next;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint32_t packets_tx;
    uint32_t packets_rx;
} __attribute__((__packed__));

#define MIN_PING_PACKET_SIZE sizeof(struct ping_packet)
#define MAX_PING_PACKET_SIZE (sizeof(struct ping_packet) + \
        sizeof(struct gps_payload) + \
        sizeof(struct ping_packet))

#define PING_TYPE(x) (x & 0xF0)
#define PING_NEXT(x) (x & 0x0F)

int start_ping_thread();

int fill_passive_payload(const char *ifname, struct passive_payload *dest);

#ifdef GATEWAY
struct interface;
int ping_all_interfaces();
int ping_interface(struct interface *ife);
#endif
//This is defined differently for both the gateway and controller
//It's called from the datapath when a packet comes in with the TUNFLAG_PING flag set
int handle_incoming_ping(struct sockaddr_storage *from_addr, struct timeval recv_time, struct interface *local_ife, struct interface *remote_ife, char *buffer, int size);

/*
 * Returns a 32-bit timestamp in microseconds.  This will wrap around once
 * every 71.58 minutes, so it should be sufficient for RTT measurements.
 */
static inline uint32_t timeval_to_usec(const struct timeval *tv)
{
    if(tv) {
        return (uint32_t)(tv->tv_sec * USEC_PER_SEC + tv->tv_usec);
    } else {
        struct timeval now;
        gettimeofday(&now, 0);
        return (uint32_t)(now.tv_sec * USEC_PER_SEC + now.tv_usec);
    }
}

void fill_ping_digest(struct ping_packet *pkt, const char *data, int len, 
        const unsigned char *key);
int verify_ping_sender(struct ping_packet *pkt, const char *data, int len, 
        const unsigned char *key);
int iszero(const unsigned char *buffer, int len);

const char *ping_err_str(int error);

#endif //_PING_H_

