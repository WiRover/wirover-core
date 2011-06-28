#ifndef DATABASE_H
#define DATABASE_H

#include <mysql/mysql.h>

#define DB_HOST "localhost"
#define DB_USER "root"
#define DB_PASS "password"
#define DB_NAME "gateways"

int init_database();
void close_database();

struct gateway;
struct gps_payload;
struct interface;

int db_update_gps(struct gateway *gw, struct gps_payload *gps);
int db_update_pings(struct gateway *gw, struct interface *ife, int rtt);

#endif /* DATABASE_H */

