#ifndef _PING_H_
#define _PING_H_

#include <sys/time.h>

#define PING_REQUEST          0x10
#define PING_REQUEST_WITH_GPS 0x11
#define PING_RESPONSE         0x20
#define PING_SECOND_RESPONSE  0x30

#define USEC_PER_SEC        1000000
#define PING_LOSS_THRESHOLD 4

struct gps_payload {
    uint8_t status;
    double  latitude;
    double  longitude;
    double  altitude;
    double  track;
    double  speed;
    double  climb;
} __attribute__((__packed__));

struct ping_packet {
    uint32_t seq_no;
    uint8_t  type;
    int8_t   link_state;
    uint16_t src_id;
    uint32_t link_id;
    uint32_t secret_word;
    uint32_t sender_ts;
    uint32_t receiver_ts;

    // Optional GPS data
    struct gps_payload gps;
} __attribute__((__packed__));

#define MIN_PING_PACKET_SIZE (sizeof(struct tunhdr) + \
        offsetof(struct ping_packet, gps))
#define MAX_PING_PACKET_SIZE (sizeof(struct tunhdr) + \
        sizeof(struct ping_packet))

int start_ping_thread();

#ifdef GATEWAY
int ping_all_interfaces(unsigned short src_port);
int ping_interface(struct interface* ife);
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

