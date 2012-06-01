#define _BSD_SOURCE /* Required for be64toh */

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
#include <endian.h>

#include "bandwidth.h"
#include "config.h"
#include "configuration.h"
#include "database.h"
#include "debug.h"
#include "gateway.h"
#include "interface.h"
#include "ping.h"
#include "timing.h"

static const char CREATE_TABLE_GATEWAYS[] = "                       \
    create table if not exists gateways (                           \
        id          int unsigned not null,                          \
        name        varchar(16) default null,                       \
        state       tinyint(1) unsigned default 0,                  \
        private_ip  varchar(46) default null,                       \
        event_time  datetime default null,                          \
        comment     text default null,                              \
        primary key (id)                                            \
    ) engine=InnoDB default charset=utf8                            \
";

static const char CREATE_TABLE_LINKS[] = "                          \
    create table if not exists links (                              \
        id          int unsigned not null auto_increment,           \
        node_id     int unsigned not null,                          \
        network     varchar(16) not null,                           \
        ip          varchar(46) default null,                       \
        state       tinyint(1) unsigned default 0,                  \
        bytes_tx    bigint unsigned default 0,                      \
        bytes_rx    bigint unsigned default 0,                      \
        month_tx    bigint unsigned default 0,                      \
        month_rx    bigint unsigned default 0,                      \
        quota       bigint unsigned default null,                   \
        avg_rtt     double default null,                            \
        avg_bw_down double default null,                            \
        avg_bw_up   double default null,                            \
        updated     timestamp not null default                      \
            current_timestamp on update current_timestamp,          \
        comment     text default null,                              \
        primary key (id),                                           \
        unique key (node_id, network),                              \
        foreign key (node_id) references gateways (id)              \
            on delete cascade on update cascade                     \
    ) engine=InnoDB default charset=utf8                            \
";

static const char CREATE_TABLE_GPS[] = "                            \
    create table if not exists gps (                                \
        id          int unsigned not null auto_increment,           \
        node_id     int unsigned not null,                          \
        time        timestamp not null default current_timestamp,   \
        status      tinyint(1) default 0,                           \
        latitude    double default null,                            \
        longitude   double default null,                            \
        altitude    double default null,                            \
        track       double default null,                            \
        speed       double default null,                            \
        climb       double default null,                            \
        primary key (id),                                           \
        unique key (node_id, time),                                 \
        foreign key (node_id) references gateways (id)              \
            on delete cascade on update cascade                     \
    ) engine=InnoDB default charset=utf8                            \
";

static const char CREATE_TABLE_PINGS[] = "                          \
    create table if not exists pings (                              \
        id          int unsigned not null auto_increment,           \
        node_id     int unsigned not null,                          \
        network     varchar(16) not null,                           \
        time        timestamp not null default current_timestamp,   \
        gps_id      int unsigned default null,                      \
        rtt         int unsigned default null,                      \
        primary key (id),                                           \
        unique key (node_id, network, time),                        \
        foreign key (node_id) references gateways (id)              \
            on delete cascade on update cascade,                    \
        foreign key (gps_id) references gps (id)                    \
            on delete set null on update cascade                    \
    ) engine=InnoDB default charset=utf8                            \
";

static const char CREATE_TABLE_BANDWIDTH[] = "                      \
    create table if not exists bandwidth (                          \
        id          int unsigned not null auto_increment,           \
        node_id     int unsigned not null,                          \
        network     varchar(16) not null,                           \
        time        timestamp not null default current_timestamp,   \
        gps_id      int unsigned default null,                      \
        bw_down     double default null,                            \
        bw_up       double default null,                            \
        type        enum ('TCP', 'UDP') default null,               \
        primary key (id),                                           \
        unique key (node_id, network, time),                        \
        foreign key (node_id) references gateways (id)              \
            on delete cascade on update cascade,                    \
        foreign key (gps_id) references gps (id)                    \
            on delete set null on update cascade                    \
    ) engine=InnoDB default charset=utf8                            \
";

static const char CREATE_TABLE_PASSIVE[] = "                        \
    create table if not exists passive (                            \
        id          int unsigned not null auto_increment,           \
        node_id     int unsigned not null,                          \
        network     varchar(16) not null,                           \
        time        timestamp not null default current_timestamp,   \
        interval_len    int unsigned default 0,                     \
        bytes_tx    bigint unsigned default 0,                      \
        bytes_rx    bigint unsigned default 0,                      \
        rate_down   double default 0,                               \
        rate_up     double default 0,                               \
        packets_tx  int unsigned default 0,                         \
        packets_rx  int unsigned default 0,                         \
        losses      int unsigned default 0,                         \
        outoforder  int unsigned default 0,                         \
        primary key (id),                                           \
        unique key (node_id, network, time),                        \
        foreign key (node_id) references gateways (id)              \
            on delete cascade on update cascade                     \
    ) engine=InnoDB default charset=utf8                            \
";

static const char *REQUIRED_TABLES[] = {
    CREATE_TABLE_GATEWAYS,
    CREATE_TABLE_LINKS,
    CREATE_TABLE_GPS,
    CREATE_TABLE_PINGS,
    CREATE_TABLE_BANDWIDTH,
    CREATE_TABLE_PASSIVE,
    NULL,
};

static int create_tables();

static MYSQL* database = 0;
static char query_buffer[1024];
static pthread_mutex_t database_lock = PTHREAD_MUTEX_INITIALIZER;

int init_database()
{
    int ret = -1;

    const config_t *config = get_config();
    const char *db_host = DEFAULT_MYSQL_HOST;
    const char *db_user = DEFAULT_MYSQL_USER;
    const char *db_pass = DEFAULT_MYSQL_PASSWORD;
    const char *db_name = DEFAULT_MYSQL_DATABASE;

    if(pthread_mutex_lock(&database_lock)) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

    if(database) {
        ret = 0;
        goto unlock_and_return;
    }

    if(config) {
        config_lookup_string(config, CONFIG_MYSQL_HOST, &db_host);
        config_lookup_string(config, CONFIG_MYSQL_USER, &db_user);
        config_lookup_string(config, CONFIG_MYSQL_PASSWORD, &db_pass);
        config_lookup_string(config, CONFIG_MYSQL_DATABASE, &db_name);
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

    if(!mysql_real_connect(database, db_host, db_user, db_pass, db_name, 0, 0, 0)) {
        DEBUG_MSG("mysql_real_connect() failed");
        mysql_close(database);
        database = 0;
        goto unlock_and_return;
    }

    if(create_tables() < 0)
        DEBUG_MSG("Warning: create_tables() failed");

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

int db_update_gateway(const struct gateway *gw, int state_change)
{
    if(!database)
        return -1;

    if(pthread_mutex_lock(&database_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

    int len;
    if(gw->state == ACTIVE) {
        char priv_ip[INET6_ADDRSTRLEN];
        ipaddr_to_string(&gw->private_ip, priv_ip, sizeof(priv_ip));

        if(state_change) {
            len = snprintf(query_buffer, sizeof(query_buffer),
                    "insert into gateways (id, state, event_time, private_ip)"
                    "values (%hu, %d, NOW(), '%s')"
                    "on duplicate key update state=%d, event_time=NOW(), private_ip='%s'",
                    gw->unique_id, gw->state, priv_ip,
                    gw->state, priv_ip);
        } else {
            len = snprintf(query_buffer, sizeof(query_buffer),
                    "insert into gateways (id, state, private_ip)"
                    "values (%hu, %d, '%s')"
                    "on duplicate key update state=%d, private_ip='%s'",
                    gw->unique_id, gw->state, priv_ip,
                    gw->state, priv_ip);
        }
    } else {
        if(state_change) {
            len = snprintf(query_buffer, sizeof(query_buffer),
                    "insert into gateways (id, state, event_time, private_ip)"
                    "values (%hu, %d, NOW(), NULL)"
                    "on duplicate key update state=%d, event_time=NOW(), private_ip=NULL",
                    gw->unique_id, gw->state, gw->state);
        } else {
            len = snprintf(query_buffer, sizeof(query_buffer),
                    "insert into gateways (id, state, private_ip)"
                    "values (%hu, %d, NULL)"
                    "on duplicate key update state=%d, private_ip=NULL",
                    gw->unique_id, gw->state, gw->state);
        }
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

int db_update_link(const struct gateway *gw, const struct interface *ife)
{
    if(!database)
        return -1;

    // Do not update database if link's network name is unknown
    if(!ife->network[0])
        return 0;

    if(pthread_mutex_lock(&database_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

    char pub_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &ife->public_ip, pub_ip, sizeof(pub_ip));

    int len = snprintf(query_buffer, sizeof(query_buffer),
            "insert into links (node_id, network, ip, avg_bw_down, avg_bw_up, "
            "avg_rtt, state, updated) values "
            "(%hu, '%s', '%s', '%f', '%f', '%f', %d, NOW()) "
            "on duplicate key update ip='%s', avg_bw_down='%f', avg_bw_up='%f', "
            "avg_rtt='%f', state=%d, updated=NOW()",
            gw->unique_id, ife->network, pub_ip, 
            ife->avg_downlink_bw, ife->avg_uplink_bw, ife->avg_rtt, ife->state,
            pub_ip, ife->avg_downlink_bw, ife->avg_uplink_bw,
            ife->avg_rtt, ife->state);
    
    int res = mysql_real_query(database, query_buffer, len);
    if(res != 0) {
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
        goto unlock_and_return;
    }

unlock_and_return:
    pthread_mutex_unlock(&database_lock);
    return res;
}

int db_update_gps(struct gateway *gw, const struct gps_payload *gps)
{
    if(!database)
        return -1;

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

int db_update_pings(const struct gateway *gw, const struct interface *ife, int rtt)
{
    if(!database)
        return -1;

    const time_t now = time(0);

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
    }

    pthread_mutex_unlock(&database_lock);
    return res;
}

int db_update_passive(const struct gateway *gw, struct interface *ife, 
                const struct passive_payload *passive)
{
    struct timeval now;
    gettimeofday(&now, 0);

    uint64_t bytes_tx = be64toh(passive->bytes_tx);
    uint64_t bytes_rx = be64toh(passive->bytes_rx);
    uint32_t packets_tx = ntohl(passive->packets_tx);
    uint32_t packets_rx = ntohl(passive->packets_rx);

    if(ife->last_passive.tv_sec == 0 ||
            bytes_tx < ife->prev_bytes_tx ||
            bytes_rx < ife->prev_bytes_rx ||
            packets_tx < ife->prev_packets_tx ||
            packets_rx < ife->prev_packets_rx) {
        memcpy(&ife->last_passive, &now, sizeof(ife->last_passive));
        ife->prev_bytes_tx = bytes_tx;
        ife->prev_bytes_rx = bytes_rx;
        ife->prev_packets_tx = packets_tx;
        ife->prev_packets_rx = packets_rx;
        return 0;
    }
    
    long time_diff = timeval_diff(&now, &ife->last_passive);
    unsigned long long bytes_tx_diff = bytes_tx - ife->prev_bytes_tx;
    unsigned long long bytes_rx_diff = bytes_rx - ife->prev_bytes_rx;
    unsigned packets_tx_diff = packets_tx - ife->prev_packets_tx;
    unsigned packets_rx_diff = packets_rx - ife->prev_packets_rx;
    double rate_up = (double)(8 * bytes_tx_diff) / (double)time_diff;
    double rate_down = (double)(8 * bytes_rx_diff) / (double)time_diff;
        
    memcpy(&ife->last_passive, &now, sizeof(ife->last_passive));
    ife->prev_bytes_tx = bytes_tx;
    ife->prev_bytes_rx = bytes_rx;
    ife->prev_packets_tx = packets_tx;
    ife->prev_packets_rx = packets_rx;

    if(!database)
        return -1;

    if(pthread_mutex_lock(&database_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

    int len = snprintf(query_buffer, sizeof(query_buffer),
            "insert into passive (node_id, network, time, interval_len, "
            "bytes_tx, bytes_rx, rate_down, rate_up, packets_tx, packets_rx) values "
            "(%hu, '%s', NOW(), %ld, %llu, %llu, '%f', '%f', %u, %u)",
            gw->unique_id, ife->network, time_diff,
            bytes_tx_diff, bytes_rx_diff,
            rate_down, rate_up,
            packets_tx_diff, packets_rx_diff);

    int res = mysql_real_query(database, query_buffer, len);
    if(res != 0) {
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
        goto unlock_and_return;
    }
    
    len = snprintf(query_buffer, sizeof(query_buffer),
            "update links set bytes_tx=bytes_tx+%llu, bytes_rx=bytes_rx+%llu, "
            "month_tx=month_tx+%llu, month_rx=month_rx+%llu, updated=NOW() "
            "where node_id=%hu and network='%s'",
            bytes_tx_diff, bytes_rx_diff, bytes_tx_diff, bytes_rx_diff,
            gw->unique_id, ife->network);
    
    res = mysql_real_query(database, query_buffer, len);
    if(res != 0) {
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
    }

unlock_and_return:
    pthread_mutex_unlock(&database_lock);
    return res;
}

int db_update_bandwidth(const struct gateway *gw, const struct interface *ife, 
                int type, double bw_down, double bw_up)
{
    if(!database)
        return -1;

    const time_t now = time(0);

    if(pthread_mutex_lock(&database_lock) != 0) {
        DEBUG_MSG("pthread_mutex_lock failed");
        return -1;
    }

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

    int len;

    if((now - gw->last_gps_time) < GPS_DATA_TIMEOUT) {
        len = snprintf(query_buffer, sizeof(query_buffer),
                "insert into bandwidth (node_id, network, gps_id, bw_down, bw_up, type) values"
                "(%hu, '%s', %u, '%f', '%f', %s)",
                gw->unique_id, ife->network, gw->last_gps_row_id,
                bw_down, bw_up, type_str);
    } else {
        len = snprintf(query_buffer, sizeof(query_buffer),
                "insert into bandwidth (node_id, network, bw_down, bw_up, type) values"
                "(%hu, '%s', '%f', '%f', %s)",
                gw->unique_id, ife->network, bw_down, bw_up, type_str);
    }

    int res = mysql_real_query(database, query_buffer, len);
    if(res != 0) {
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
    }

    pthread_mutex_unlock(&database_lock);
    return res;
}

/*
 * Create all of the required tables if they do not already exist.
 *
 * Must be called with database_lock held.
 */
static int create_tables()
{
    int res;

    if(!database)
        return -1;

    const char **table = REQUIRED_TABLES;
    while(*table) {
        res = mysql_real_query(database, *table, strlen(*table));
        if(res != 0) 
            DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));

        table++;
    }

    return 0;
}

