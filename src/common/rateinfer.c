
#include "debug.h"
#include "rateinfer.h"

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

