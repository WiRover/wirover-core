#ifndef DATABASE_H
#define DATABASE_H

#include <mysql/mysql.h>

int init_database();
void close_database();

struct gateway;
struct gps_payload;
struct passive_payload;
struct interface;

int verify_hash(char* hash);
void *db_write_loop(void *arg);
int db_update_gateway(const struct gateway *gw, int state_change);
int db_update_link(const struct gateway *gw, const struct interface *ife);
int db_update_gps(struct gateway *gw, const struct gps_payload *gps);
int db_update_pings(const struct gateway *gw, const struct interface *ife, int rtt);
int db_update_passive(const struct gateway *gw, struct interface *ife, 
        const struct passive_payload *passive);
int db_update_bandwidth(const struct gateway *gw, const struct interface *ife,
        int type, double bw_down, double bw_up);

#endif /* DATABASE_H */

