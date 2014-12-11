#ifndef RATEINFER_H
#define RATEINFER_H

#include <stdint.h>
#include "circular_counter.h"
#include "config.h"

/* Structure for implementing rate control on a flow or interface. */
struct rate_control_info {
    struct timeval start_time;
    struct circular_counter tx_counter;
    long capacity;
};

struct packet_burst {
    uint32_t local_start; // Timestamps in usecs
    uint32_t local_end;

    uint32_t remote_start; // Timestamps in usecs
    uint32_t remote_end;

    uint32_t seq_start;
    uint32_t seq_end;

    uint32_t first_packet_size;
    uint32_t last_packet_size;
    
    /* packets_received < (seq_end - seq_start + 1) if there were losses. */
    uint32_t bytes_received;
    uint32_t packets_received;
};

void init_interface_rate_control_info(struct rate_control_info *rcinfo);
int has_capacity(struct rate_control_info *rcinfo, const struct timeval *now);
void update_tx_rate(struct rate_control_info *rcinfo, int size);

void update_burst(struct packet_burst *burst, uint32_t local_ts, uint32_t remote_ts, 
        uint32_t seq, uint32_t size);
void next_burst(struct packet_burst *burst);

static inline int burst_packets(const struct packet_burst *burst)
{
    return ((int)burst->seq_end - (int)burst->seq_start + 1);
}

/* Returns received data rate in Mbps. */
static inline double burst_rx_rate(const struct packet_burst *burst)
{
    return (8.0 * (double)burst->bytes_received / (burst->local_end - burst->local_start));
}

/* Returns the burst duration (local side) in microseconds. */
static inline int burst_duration(const struct packet_burst *burst)
{
    return ((int)burst->local_end - (int)burst->local_start);
}

#endif /* RATEINFER_H */
