#include <sys/time.h>

#include "debug.h"
#include "rateinfer.h"
#include "timing.h"

void init_interface_rate_control_info(struct rate_control_info *rcinfo)
{
    gettimeofday(&rcinfo->start_time, NULL);

    // 5 bins * 20,000 us each = 100 ms time window for estimating rate.
    ccount_init(&rcinfo->tx_counter, 5, 20000);

    // Artificially limit to 1 Mbps for testing.
    // Ultimately, we will limit this based on predicted link capacity or policy.
    // 1 Mbps = 12500 bytes / 100 ms.
    rcinfo->capacity = 12500;
}

/* Test if the target has remaining capacity to send another packet.  Returns
 * true/false.  This could be augmented to consider the size of the packet to
 * be sent. */
int has_capacity(struct rate_control_info *rcinfo, const struct timeval *now)
{
    long t = timeval_diff(now, &rcinfo->start_time);
    long count = ccount_sum(&rcinfo->tx_counter, t);
    return (count < rcinfo->capacity);
}

/* Call after sending a packet of the given size in bytes to increment the
 * counter. */
void update_tx_rate(struct rate_control_info *rcinfo, int size)
{
    struct timeval send_time;
    gettimeofday(&send_time, NULL);

    long t = timeval_diff(&send_time, &rcinfo->start_time);
    ccount_inc(&rcinfo->tx_counter, t, size);
}

void update_burst(struct packet_burst *burst, uint32_t local_ts, uint32_t remote_ts, uint32_t seq, uint32_t size)
{
    int diff = (int)remote_ts - (int)burst->remote_end;
    int dur = burst_duration(burst);

    if (burst->bytes_received == 0) {
        burst->local_start = local_ts;
        burst->remote_start = remote_ts;
        burst->seq_start = seq;
        burst->first_packet_size = size;
    } else if(diff >= 100000 || dur >= 100000) {
//        DEBUG_MSG("Burst: %u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
//            burst->local_start,
//            burst->local_end,
//            burst->remote_start,
//            burst->remote_end,
//            burst->seq_start,
//            burst->seq_end,
//            burst->first_packet_size,
//            burst->last_packet_size,
//            burst->bytes_received,
//            burst->packets_received);

        burst->local_start = local_ts;
        burst->remote_start = remote_ts;
        burst->seq_start = seq;

        burst->first_packet_size = size;
        burst->bytes_received = 0;
        burst->packets_received = 0;
    }

    burst->local_end = local_ts;
    burst->remote_end = remote_ts;
    burst->seq_end = seq;

    burst->last_packet_size = size;
    burst->bytes_received += size;
    burst->packets_received++;
}

void next_burst(struct packet_burst *burst)
{
    burst->local_start = burst->local_end;
    burst->remote_start = burst->remote_end;
    burst->seq_start = burst->seq_end;

    burst->first_packet_size = burst->last_packet_size;
    burst->bytes_received = burst->last_packet_size;
    burst->packets_received = 1;
}

