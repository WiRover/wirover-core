#ifndef _PING_H_
#define _PING_H_

#include <stdint.h>
#include <sys/time.h>

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
#define RTT_EWMA_WEIGHT         0.2

#define PROC_NET_DEV            "/proc/net/dev"
#define PROC_NET_DEV_STAT_COLS  8

struct ping_packet {
    uint8_t  type;
    uint32_t seq_no;
    int8_t   link_state;
    uint16_t src_id;
    uint32_t link_id;
    uint32_t secret_word;
    uint32_t sender_ts;
    uint32_t receiver_ts;
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

#define MIN_PING_PACKET_SIZE (sizeof(struct tunhdr) + \
        sizeof(struct ping_packet))
#define MAX_PING_PACKET_SIZE (sizeof(struct tunhdr) + \
        sizeof(struct ping_packet) + \
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

#endif //_PING_H_

