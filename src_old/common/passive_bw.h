/*
 * passive_bw.h
 */

#ifndef PASSIVE_BW_H
#define PASSIVE_BW_H

struct link;
struct link_iterator;

struct passive_stats {
    struct timeval     start_time;
    double             rate_down;
    double             rate_up;
    unsigned long long bytes_sent;
    unsigned long long bytes_recvd;
    unsigned int       packets;
    unsigned int       packets_lost;
    unsigned int       out_of_order_packets;
    unsigned int       age;
};

// typedef for a passive measurement callback function
// We use link_iterator so that wicontroller code can access the wigateway structure.
typedef void (*passive_callback_t)(struct link_iterator*, struct passive_stats*);

int startPassiveThread();
void setPassiveCallback(passive_callback_t func);

void storePassiveStats(struct link* link, struct passive_stats* dest);
void computePassiveStatsDiff(struct passive_stats* diff,
     struct passive_stats* end, struct passive_stats* start);

// vim: set et ts=4 sw=4 cindent:

#endif //PASSIVE_BW_H

