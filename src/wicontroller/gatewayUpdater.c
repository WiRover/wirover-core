/* vim: set et ts=4 sw=4: */

#include <arpa/inet.h>
#include <errno.h>
#include <gps.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "selectInterface.h"
#include "../common/handleTransfer.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/contChan.h"
#include "../common/reOrderPackets.h"
#include "../common/utils.h"
#include "../common/tunnelInterface.h"
#include "../common/packet_debug.h"
#include "../common/special.h"

#include "gatewayUpdater.h"

// MySQL-dependent code is only compiled if this flag is set.
#ifdef WITH_MYSQL

char local_buf[MAX_LINE];

#define WR_HOST "localhost"
#define WR_USER "wirover"
#define WR_PASS ""
#define WR_NAME "gateways"

#define GW_TABLE "gateways"
#define GW_NAME  "name"
#define GW_PKEY  "k"

#define GW_NODE "node"
#define GW_RX "rx"
#define GW_TX "tx"
#define GW_LOSS "loss"
#define GW_LAT "latitude"
#define GW_LON "longitude"
#define GW_ALT "altitude"
#define GW_BW1 "bw1"

static MYSQL*           gateways_database = NULL;
static pthread_mutex_t  db_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Obtains a connection to the gateways database.
 */
int gw_init_db()
{
    int ret = FAILURE;

    // Lock the database
    if(pthread_mutex_lock(&db_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return FAILURE;
    }

    // Check if it has already been initialized by the time we obtain the mutex
    // lock.
    if(gateways_database) {
        ret = SUCCESS;
        goto unlock_and_return;
    }

    gateways_database = mysql_init(NULL);
    if(!gateways_database) {
        DEBUG_MSG("mysql_init() failed");
        goto unlock_and_return;
    }

    my_bool yes = 1;
    if(mysql_options(gateways_database, MYSQL_OPT_RECONNECT, &yes) != 0) {
        DEBUG_MSG("Warning: mysql_option failed");
    }

    if(! mysql_real_connect(
            gateways_database,
            WR_HOST,
            WR_USER,
            WR_PASS,
            WR_NAME,
            0,
            NULL,
            0)) {
        DEBUG_MSG("mysql_real_connect() failed");

        mysql_close(gateways_database);
        gateways_database = 0;

        goto unlock_and_return;
    }

    ret = SUCCESS;

unlock_and_return:
    pthread_mutex_unlock(&db_lock);
    return ret;
}

void gw_close()
{
    if(gateways_database) {
        mysql_close(gateways_database);
        gateways_database = 0;
    }
}

/**
 * Updates the gateways table with the given wigateway table. The record in the
 * table for the gateway is created if it does not already exist.
 */
void gw_update_status(struct wigateway *gw)
{
    if(!gateways_database) {
        return;
    }

    int err;
    char query[1000];
    int len;

    len = snprintf(query, sizeof(query),
                   "select id from gateways where id=%u",
                   gw->node_id);
    
    if(pthread_mutex_lock(&db_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return;
    }

    err = mysql_real_query(gateways_database, query, len);
    if(err != 0) {
        snprintf(local_buf, sizeof(local_buf),
                 "mysql_query failed: %s",
                 mysql_error(gateways_database));
        DEBUG_MSG(local_buf);
        goto unlock_and_return;
    }

    MYSQL_RES *qr = mysql_store_result(gateways_database);
    if(!qr) {
        snprintf(local_buf, sizeof(local_buf),
                 "mysql_store_result failed: %s",
                 mysql_error(gateways_database));
        DEBUG_MSG(local_buf);
        goto unlock_and_return;
    }

    int nr = mysql_num_rows(qr);
    
    mysql_free_result(qr);

    // if record does not exist, create it, otherwise update it.
    if(nr == 0) {
        if(gw->state == GW_STATE_ACTIVE) {
            len = snprintf(query, sizeof(query),
                    "insert into gateways (id, state, event_time, private_ip)"
                    " values (%u, %u, FROM_UNIXTIME(%lu), '%s')",
                    gw->node_id, gw->state,
                    (unsigned long)gw->last_state_change,
                    gw->p_private_ip);
        } else {
            len = snprintf(query, sizeof(query),
                    "insert into gateways (id, state, event_time, private_ip)"
                    " values (%u, %u, FROM_UNIXTIME(%lu), NULL)",
                    gw->node_id, gw->state,
                    (unsigned long)gw->last_state_change);
        }
        
        err = mysql_real_query(gateways_database, query, len);
        if(err != 0) {
            snprintf(local_buf, sizeof(local_buf),
                     "mysql_query failed: %s",
                     mysql_error(gateways_database));
            DEBUG_MSG(local_buf);
            goto unlock_and_return;
        }
    } else {
        if(gw->state == GW_STATE_ACTIVE) {
            len = snprintf(query, sizeof(query),
                    "update gateways set state=%u, event_time=FROM_UNIXTIME(%lu),"
                    " private_ip='%s' where id=%u and state!=%u",
                    gw->state, (unsigned long)gw->last_state_change,
                    gw->p_private_ip, gw->node_id, gw->state);
        } else {
            len = snprintf(query, sizeof(query),
                    "update gateways set state=%u, event_time=FROM_UNIXTIME(%lu),"
                    " private_ip=NULL where id=%u and state!=%u",
                    gw->state, (unsigned long)gw->last_state_change,
                    gw->node_id, gw->state);
        }

        err = mysql_real_query(gateways_database, query, len);
        if(err != 0) {
            snprintf(local_buf, sizeof(local_buf),
                     "mysql_query failed: %s",
                     mysql_error(gateways_database));
            DEBUG_MSG(local_buf);
            goto unlock_and_return;
        }
    }

unlock_and_return:
    pthread_mutex_unlock(&db_lock);
}

void gw_update_link(struct wigateway* gw, struct link* link)
{
    if(!gateways_database) {
        return;
    }

    int err;
    char query[1000];
    int len;

    len = snprintf(query, sizeof(query),
                   "select node_id,network from links where node_id=%u and network='%s'",
                   gw->node_id, link->network);
    
    if(pthread_mutex_lock(&db_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return;
    }

    err = mysql_real_query(gateways_database, query, len);
    if(err != 0) {
        snprintf(local_buf, sizeof(local_buf),
                 "mysql_query failed: %s",
                 mysql_error(gateways_database));
        DEBUG_MSG(local_buf);
        goto unlock_and_return;
    }

    MYSQL_RES *qr = mysql_store_result(gateways_database);
    if(!qr) {
        snprintf(local_buf, sizeof(local_buf),
                 "mysql_store_result failed: %s",
                 mysql_error(gateways_database));
        DEBUG_MSG(local_buf);
        goto unlock_and_return;
    }

    int nr = mysql_num_rows(qr);
    
    mysql_free_result(qr);

    // if record does not exist, create it, otherwise update it.
    if(nr == 0) {
        len = snprintf(query, sizeof(query),
               "insert into links (node_id, network, ip, bytes_tx, bytes_rx, month_tx, month_rx, avg_bw_down, avg_bw_up, avg_rtt, state) values (%u, '%s', '%s', %llu, %llu, %llu, %llu, '%f', '%f', '%f', %d)",
               gw->node_id, link->network, link->p_ip, link->bytes_sent, 
               link->bytes_recvd, link->month_sent, link->month_recvd, 
               link->avg_active_bw_down, link->avg_active_bw_up, link->avg_rtt,
               link->state);
        
        err = mysql_real_query(gateways_database, query, len);
        if(err != 0) {
            snprintf(local_buf, sizeof(local_buf),
                     "mysql_query failed: %s",
                     mysql_error(gateways_database));
            DEBUG_MSG(local_buf);
            goto unlock_and_return;
        }
    } else {
        len = snprintf(query, sizeof(query),
                "update links set ip='%s', bytes_tx=%llu, bytes_rx=%llu, avg_bw_down='%f', avg_bw_up='%f', avg_rtt='%f', state=%d where node_id=%u and network='%s'",
                link->p_ip, link->bytes_sent, link->bytes_recvd,
                link->avg_active_bw_down, link->avg_active_bw_up, link->avg_rtt,
                link->state, gw->node_id, link->network);

        err = mysql_real_query(gateways_database, query, len);
        if(err != 0) {
            snprintf(local_buf, sizeof(local_buf),
                     "mysql_query failed: %s",
                     mysql_error(gateways_database));
            DEBUG_MSG(local_buf);
            goto unlock_and_return;
        }
    }

unlock_and_return:
    pthread_mutex_unlock(&db_lock);
}

void gw_update_gps(struct wigateway* gw, struct gps_payload* gpsData)
{
    char query[1000];

    const time_t now = time(0);
    if( (now - gw->lastGpsTime) < MIN_GPS_TIME_DIFF ) {
        // This GPS point is a duplicate of the previous.
        return;
    }

    int len = snprintf(query, sizeof(query),
            "insert into gps (node_id, status, latitude, longitude,"
            "altitude, track, speed, climb) values ('%d', '%d', '%f',"
            "'%f', '%f', '%f', '%f', '%f')",
            gw->node_id, gpsData->status, gpsData->latitude, gpsData->longitude,
            gpsData->altitude, gpsData->track, gpsData->speed, gpsData->climb);
    
    if(pthread_mutex_lock(&db_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return;
    }

    int err = mysql_real_query(gateways_database, query, len);
    if(err != 0) {
        snprintf(local_buf, sizeof(local_buf), "mysql_query() failed: %s",
                mysql_error(gateways_database));
        DEBUG_MSG(local_buf);
        goto unlock_and_return;
    }

    gw->lastGpsTime = now;
    gw->lastGpsRowId = mysql_insert_id(gateways_database);

unlock_and_return:
    pthread_mutex_unlock(&db_lock);
}

void gw_update_pings(struct wigateway* gw, struct link* link, int rtt)
{
    char query[1000];
    int len;

    const time_t now = time(0);
    
    // If possible, associate the ping with the GPS point.
    if( (now - gw->lastGpsTime) <= GPS_MAX_AGE ) {
        len = snprintf(query, sizeof(query),
                 "insert into pings (node_id, network, gps_id, rtt) values (%d, '%s', %u, %d)",
                 gw->node_id, link->network, gw->lastGpsRowId, rtt);
    } else {
        len = snprintf(query, sizeof(query),
                 "insert into pings (node_id, network, rtt) values (%d, '%s', %d)",
                 gw->node_id, link->network, rtt);
    }
   
    safe_mysql_query(gateways_database, query, len);
}

void gw_update_activebw(struct wigateway* gw, struct link* link, 
        int type, double bw_down, double bw_up)
{
    char query[1000];
    int len;

    const time_t now = time(0);

    const char *type_str;
    switch(type) {
        case BW_UDP:
            type_str = "'UDP'";
            break;
        case BW_TCP:
            type_str = "'TCP'";
            break;
        default:
            type_str = "NULL";
            break;
    }

    // If possible, associate the bandwidth measurement with the GPS point.
    if( (now - gw->lastGpsTime) <= GPS_MAX_AGE ) {
        len = snprintf(query, sizeof(query),
             "insert into bandwidth (node_id, network, gps_id, bw_down, bw_up, type) "
             "values ('%d', '%s', %u, '%f', '%f', %s)",
             gw->node_id, link->network, gw->lastGpsRowId, bw_down, bw_up, type_str);
    } else {
        len = snprintf(query, sizeof(query),
             "insert into bandwidth (node_id, network, bw_down, bw_up, type) "
             "values ('%d', '%s', '%f', '%f', %s)",
             gw->node_id, link->network, bw_down, bw_up, type_str);
    }

    safe_mysql_query(gateways_database, query, len);
}

void gw_update_passive(struct link_iterator* link_iter, struct passive_stats* stats)
{
    char query[1000];
    
    struct wigateway* __restrict__ gw = link_iter->gw;
    struct link* __restrict__ link = link_iter->link;

    int len = snprintf(query, sizeof(query),
        "insert into passive (node_id, network, time, interval_len, bytes_tx, bytes_rx, rate_down, rate_up, packets, losses, outoforder) values (%d, '%s', FROM_UNIXTIME(%lu), %u, %llu, %llu, '%f', '%f', %u, %u, %u)",
        gw->node_id, link->network, stats->start_time.tv_sec, stats->age,
        stats->bytes_sent, stats->bytes_recvd,
        stats->rate_down, stats->rate_up,
        stats->packets, stats->packets_lost, stats->out_of_order_packets);

    safe_mysql_query(gateways_database, query, len);

    len = snprintf(query, sizeof(query),
        "update links set month_tx=month_tx+%llu, month_rx=month_rx+%llu where node_id=%u and network='%s'",
        stats->bytes_sent, stats->bytes_recvd, gw->node_id, link->network);

    safe_mysql_query(gateways_database, query, len);
}

int gw_query_quota(const struct wigateway* gw, const struct link* link,
                   struct link_quota_stats* stats)
{
    assert(gw);
    assert(link);
    assert(stats);

    int ret = FAILURE;
    char query[1000];

    int len = snprintf(query, sizeof(query),
            "select bytes_tx,bytes_rx,quota from links where node_id=%d and network='%s' limit 1",
            gw->node_id, link->network);

    if(pthread_mutex_lock(&db_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return FAILURE;
    }

    int err = mysql_real_query(gateways_database, query, len);
    if(err != 0) {
        snprintf(local_buf, sizeof(local_buf), "mysql_query() failed: %s",
                mysql_error(gateways_database));
        DEBUG_MSG(local_buf);
        goto unlock_and_return;
    }

    MYSQL_RES *qr = mysql_store_result(gateways_database);
    if(!qr) {
        snprintf(local_buf, sizeof(local_buf),
                 "mysql_store_result failed: %s",
                 mysql_error(gateways_database));
        DEBUG_MSG(local_buf);
        goto unlock_and_return;
    }

    MYSQL_ROW row = mysql_fetch_row(qr);
    if(!row) {
        snprintf(local_buf, sizeof(local_buf), "Entry missing for node %d network %s\n",
                gw->node_id, link->network);
        DEBUG_MSG(local_buf);
        mysql_free_result(qr);
        goto unlock_and_return;
    }
   
    stats->bytes_tx = row[0] ? atoll(row[0]) : 0;
    stats->bytes_rx = row[1] ? atoll(row[1]) : 0;
    stats->quota    = row[2] ? atoll(row[2]) : -1;

    mysql_free_result(qr);

    ret = SUCCESS;

unlock_and_return:
    // Do not return without unlocking the mutex.
    pthread_mutex_unlock(&db_lock);
    
    return ret;
}

/*
 * SAFE MYSQL QUERY
 *
 * Executes mysql_query in a thread-safe way.  Basically, all mysql functions
 * need to be protected by a mutex, because they are not thread-safe.
 *
 * Warning: This only works for queries that produce no results.
 * You want to avoid a situation like this:
 *
 *     query1 ... query2 ... try to get results from query1 and die
 *
 * Returns either SUCCESS or FAILURE.
 */
int safe_mysql_query(MYSQL* db, char* query, unsigned query_len)
{
    if(!db) {
        return FAILURE;
    }

    if(pthread_mutex_lock(&db_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return FAILURE;
    }

    int rtn = SUCCESS;

    int err = mysql_real_query(db, query, query_len);
    if(err != 0) {
        snprintf(local_buf, sizeof(local_buf), "mysql_query() failed: %s", mysql_error(db));
        DEBUG_MSG(local_buf);
        rtn = FAILURE;
    }

    // Do not return without unlocking the mutex.
    pthread_mutex_unlock(&db_lock);
    
    return rtn;
}

#endif //WITH_MYSQL

