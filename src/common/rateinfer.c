#include <sys/time.h>

#include "debug.h"
#include "rateinfer.h"
#include "timing.h"

void init_rate_control_info(struct rate_control_info *rcinfo)
{
    gettimeofday(&rcinfo->start_time, NULL);
    rcinfo->start_index = 0;
    memset(rcinfo->tx_counts, 0, sizeof(rcinfo->tx_counts));
}

static int rotate_counts(struct rate_control_info *rcinfo, const struct timeval *send_time)
{
    long diff = timeval_diff(send_time, &rcinfo->start_time);
    long offset = diff / RATE_CONTROL_INTERVAL;
    
    if (offset >= 0 && offset < RATE_CONTROL_BINS) {
        return (rcinfo->start_index + offset) % RATE_CONTROL_BINS;
    } else if(offset >= RATE_CONTROL_BINS && offset < 2*RATE_CONTROL_BINS) {
        long rotate = offset - RATE_CONTROL_BINS + 1;
        for (int i = 0; i < rotate; i++) {
            rcinfo->tx_counts[rcinfo->start_index] = 0;
            rcinfo->start_index = (rcinfo->start_index + 1) % RATE_CONTROL_BINS;
        }
        rcinfo->start_time.tv_usec += RATE_CONTROL_INTERVAL * rotate;
        if (rcinfo->start_time.tv_usec > USEC_PER_SEC) {
            rcinfo->start_time.tv_usec -= USEC_PER_SEC;
            rcinfo->start_time.tv_sec++;
        }
        return (rcinfo->start_index - 1 + RATE_CONTROL_BINS) % RATE_CONTROL_BINS;
    } else {
        memcpy(&rcinfo->start_time, send_time, sizeof(rcinfo->start_time));
        rcinfo->start_index = 0;
        memset(rcinfo->tx_counts, 0, sizeof(rcinfo->tx_counts));
        return 0;
    }
}

int has_capacity(struct rate_control_info *rcinfo, const struct timeval *now)
{
    int index = rotate_counts(rcinfo, now);
    int count = 0;

    // Look at the past 100ms.
    for (int i = 0; i < 5; i++) {
        count += rcinfo->tx_counts[(index - i + RATE_CONTROL_BINS) % RATE_CONTROL_BINS];
    }

    // Artificially limit to 1 Mbps for testing.
    // Ultimately, we will limit this based on predicted link capacity.
    return (count < 12500);
}

void update_tx_rate(struct rate_control_info *rcinfo, int size)
{
    struct timeval send_time;
    gettimeofday(&send_time, NULL);

    int index = rotate_counts(rcinfo, &send_time);
    rcinfo->tx_counts[index] += size;
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

