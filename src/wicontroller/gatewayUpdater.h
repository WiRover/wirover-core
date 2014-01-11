/* vim: set et ts=4 sw=4: */
#ifndef GATEWAY_UPDATER_H
#define GATEWAY_UPDATER_H

#include <mysql/mysql.h>
#include <mysql/my_global.h>

// mysql redefines version
#undef VERSION

#define GPS_MAX_AGE             10
#define MIN_GPS_TIME_DIFF       2

#include "../common/parameters.h"

#ifdef WITH_MYSQL

struct wigateway;
struct link;
struct link_iterator;
struct gps_payload;
struct passive_stats;

int  gw_init_db();
void gw_close();

void gw_update_status(struct wigateway *gw);
void gw_update_link(struct wigateway* gw, struct link* link);
void gw_update_gps(struct wigateway* gw, struct gps_payload* gpsData);
void gw_update_pings(struct wigateway* gw, struct link* link, int rtt);
void gw_update_activebw(struct wigateway* gw, struct link* link, 
        int type, double bw_down, double bw_up);
void gw_update_passive(struct link_iterator* link_iter, struct passive_stats* stats);

struct link_quota_stats {
    unsigned long long  bytes_tx;
    unsigned long long  bytes_rx;
    unsigned long long  quota;
};
int gw_query_quota(const struct wigateway* gw, const struct link* link,
                   struct link_quota_stats* stats);

int safe_mysql_query(MYSQL* db, char* query, unsigned query_len);

#endif //WITH_MYSQL

#endif /* GATEWAY_UPDATER_H */

