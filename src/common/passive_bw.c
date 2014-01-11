/*
 * passive_bw.c
 */

#include <signal.h>

#include "../common/utils.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/tunnelInterface.h"
#include "../common/contChan.h"
#include "../common/special.h"
#include "../common/handleTransfer.h"

#include "../common/passive_bw.h"

static char local_buf[MAX_LINE];

static pthread_t passive_thread;
static passive_callback_t passive_callback = 0;

static void* passiveThreadFunc(void* arg);
static void updatePassiveMeasurements(struct link_iterator* link_iter);
static int shouldReport(struct passive_stats* running_diff, struct passive_stats* recent_diff);
static void reportPassiveMeasurements(struct link_iterator* link_iter, struct passive_stats* report);

/*
 * START PASSIVE BANDWIDTH
 */
int startPassiveThread()
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if(pthread_create(&passive_thread, &attr, passiveThreadFunc, 0) != 0) {
        DEBUG_MSG("pthread_create failed");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);

    return SUCCESS;
}

/*
 * SET PASSIVE CALLBACK
 */
void setPassiveCallback(passive_callback_t func)
{
    passive_callback = func;
}

/*
 * STORE PASSIVE STATS
 */
void storePassiveStats(struct link* link, struct passive_stats* dest)
{
    assert(link != 0 && dest != 0);
    
    gettimeofday(&dest->start_time, 0);
    dest->rate_down = 0.0;
    dest->rate_up = 0.0;
    dest->bytes_sent = link->bytes_sent;
    dest->bytes_recvd = link->bytes_recvd;
    dest->packets = link->packets;
    dest->packets_lost = link->packets_lost;
    dest->out_of_order_packets = link->out_of_order_packets;
    dest->age = 0;
}

/*
 * COMPUTE PASSIVE STATS DIFF
 *
 * The passive measurements are stored as cumulative values.  This function
 * computes the statistics for the interval between start and end (eg, bytes
 * sent during that interval).
 */
void computePassiveStatsDiff(struct passive_stats* diff, struct passive_stats* end, struct passive_stats* start)
{
    assert(diff != 0 && end != 0 && start != 0);

    memcpy(&diff->start_time, &start->start_time, sizeof(diff->start_time));
    diff->age = elapsedTime(&start->start_time, &end->start_time);

    diff->rate_down = 8.0 * (end->bytes_recvd - start->bytes_recvd) / diff->age;
    diff->rate_up = 8.0 * (end->bytes_sent - start->bytes_sent) / diff->age;

    diff->bytes_sent = end->bytes_sent - start->bytes_sent;
    diff->bytes_recvd = end->bytes_recvd - start->bytes_recvd;
    diff->packets = end->packets - start->packets;
    diff->packets_lost = end->packets_lost - start->packets_lost;
    diff->out_of_order_packets = end->out_of_order_packets - start->out_of_order_packets;
}

/*
 * PASSIVE THREAD FUNC
 */
void* passiveThreadFunc(void* arg)
{
    // Let another thread handle these signals
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &sigset, 0);

    while(!getQuitFlag()) {
        struct link_iterator iter;
        initInterfaceIterator(&iter, 0);

        struct link* ife = iter.link;
        while(ife) {
            if(ife->state == ACTIVE) {
                updatePassiveMeasurements(&iter);
            }

            ife = nextInterface(&iter);
        }

        safe_usleep(PASSIVE_INTERVAL);
    }

    return 0;
}

/*
 * UPDATE PASSIVE MEASUREMENTS
 */
void updatePassiveMeasurements(struct link_iterator* link_iter)
{
    assert(link_iter != 0);

    struct link* link = link_iter->link;
    assert(link != 0);

    struct passive_stats curr_stats;
    struct passive_stats recent_diff;
    struct passive_stats running_diff;
    
    // Get the current measurements (eg. bytes sent)
    storePassiveStats(link, &curr_stats);

    // Compute the change between the last time this was called to the present
    computePassiveStatsDiff(&recent_diff, &curr_stats, &link->pstats_recent);

    // Compute the change over the running interval up until the last time this was called
    computePassiveStatsDiff(&running_diff, &link->pstats_recent, &link->pstats_running);

    // Check if the running measurement is too old, or the new measurement is significantly different
    if(shouldReport(&running_diff, &recent_diff)) {
        // Report the running measurement
        reportPassiveMeasurements(link_iter, &running_diff);

        // Now the most recent measurement becomes the running measurement
        memcpy(&link->pstats_running, &link->pstats_recent, sizeof(link->pstats_running));
    }

    // Copy the current measurement to be used as the recent measurement the next time around
    memcpy(&link->pstats_recent, &curr_stats, sizeof(link->pstats_recent));
}

/*
 * SHOULD REPORT
 *
 * Determines if any of the passive measurements has changed significantly.
 */
int shouldReport(struct passive_stats* running_diff, struct passive_stats* recent_diff)
{
    assert(running_diff != 0 && recent_diff != 0);

    // Have we had a significant number of packet losses?
    if(running_diff->packets_lost >= PASSIVE_LOSS_THRESH) {
        return 1;
    }

    // Have we had a significant number of out of order packets?
    if(running_diff->out_of_order_packets >= PASSIVE_LOSS_THRESH) {
        return 1;
    }

    // Has downlink rate changed significantly?
    double down_diff = fabs(recent_diff->rate_down - running_diff->rate_down);
    double down_change = down_diff / running_diff->rate_down;
    if(down_diff >= PASSIVE_RATECHANGE_MIN &&
        (isnan(down_change) || down_change >= PASSIVE_RATECHANGE_THRESH)) {
        return 1;
    }

    // Likewise for uplink rate
    double up_diff = fabs(recent_diff->rate_up - running_diff->rate_up);
    double up_change = up_diff / running_diff->rate_up;
    if(up_diff >= PASSIVE_RATECHANGE_MIN &&
        (isnan(up_change) || up_change >= PASSIVE_RATECHANGE_THRESH)) {
        return 1;
    }

    // Have we waited the maximum amount of time before reporting?
    if(running_diff->age >= PASSIVE_TIME_THRESH) {
        return 1;
    }

    // Nothing interesting to report
    return 0;
}

/*
 * REPORT PASSIVE MEASUREMENTS
 */
void reportPassiveMeasurements(struct link_iterator* link_iter, struct passive_stats* report)
{
    assert(link_iter != 0 && report != 0);

    struct link* link = link_iter->link;
    assert(link != 0);

    snprintf(local_buf, sizeof(local_buf),
             "Passive for link %d (%s) - sent: %llu (%f) recvd: %llu (%f) lost: %u oops: %u age: %f",
             link->id, link->ifname, report->bytes_sent, report->rate_up, report->bytes_recvd, report->rate_down,
             report->packets_lost, report->out_of_order_packets, (report->age / 1000000.0));
    STATS_MSG(local_buf);

    if(passive_callback) {
        passive_callback(link_iter, report);
    }
}

// vim: set et ts=4 sw=4 cindent:

