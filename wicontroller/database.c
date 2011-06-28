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

#include "config.h"
#include "database.h"
#include "debug.h"
#include "gateway.h"
#include "interface.h"
#include "ping.h"

static MYSQL* database = 0;
static char query_buffer[1024];
static pthread_mutex_t database_lock = PTHREAD_MUTEX_INITIALIZER;

int init_database()
{
    int ret = -1;

    if(pthread_mutex_lock(&database_lock)) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

    if(database) {
        ret = 0;
        goto unlock_and_return;
    }

    database = mysql_init(0);
    if(!database) {
        DEBUG_MSG("mysql_init() failed");
        goto unlock_and_return;
    }
    
    const my_bool yes = 1;
    if(mysql_options(database, MYSQL_OPT_RECONNECT, &yes) != 0) {
        DEBUG_MSG("Warning: mysql_option failed");
    }

    if(!mysql_real_connect(database, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, 0, 0)) {
        DEBUG_MSG("mysql_real_connect() failed");
        mysql_close(database);
        database = 0;
        goto unlock_and_return;
    }

    ret = 0;

unlock_and_return:
    pthread_mutex_unlock(&database_lock);
    return ret;
}

void close_database()
{
    if(pthread_mutex_lock(&database_lock)) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return;
    }

    mysql_close(database);
    database = 0;
}

int db_update_gps(struct gateway *gw, struct gps_payload *gps)
{
    const time_t now = time(0);
    if(now == gw->last_gps_time) {
        // Avoid adding a duplicate.
        return -1;
    }

    if(pthread_mutex_lock(&database_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

    int len = snprintf(query_buffer, sizeof(query_buffer),
            "insert into gps (node_id, status, latitude, longitude,"
            "altitude, track, speed, climb) values ('%hu', '%d', '%f',"
            "'%f', '%f', '%f', '%f', '%f')",
            gw->unique_id, gps->status, gps->latitude, gps->longitude,
            gps->altitude, gps->track, gps->speed, gps->climb);

    int res = mysql_real_query(database, query_buffer, len);
    if(res != 0) {
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
        goto unlock_and_return;
    }

    gw->last_gps_time = now;
    gw->last_gps_row_id = mysql_insert_id(database);

unlock_and_return:
    pthread_mutex_unlock(&database_lock);
    return res;
}

int db_update_pings(struct gateway *gw, struct interface *ife, int rtt)
{
    const time_t now = time(0);
    if(now == gw->last_gps_time) {
        // Avoid adding a duplicate.
        return -1;
    }

    if(pthread_mutex_lock(&database_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

    int len;

    if((now - gw->last_gps_time) < GPS_DATA_TIMEOUT) {
        len = snprintf(query_buffer, sizeof(query_buffer),
                "insert into pings (node_id, network, gps_id, rtt) values"
                "(%hu, '%s', %u, %d)",
                gw->unique_id, ife->network, gw->last_gps_row_id, rtt);
    } else {
        len = snprintf(query_buffer, sizeof(query_buffer),
                "insert into pings (node_id, network, rtt) values"
                "(%hu, '%s', %d)",
                gw->unique_id, ife->network, rtt);
    }

    int res = mysql_real_query(database, query_buffer, len);
    if(res != 0) {
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
        goto unlock_and_return;
    }

unlock_and_return:
    pthread_mutex_unlock(&database_lock);
    return res;
}

