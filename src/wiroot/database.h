#ifndef _DATABASE_H_
#define _DATABASE_H_

#define MAX_QUERY_LEN 1024

// The unique id is stored as a char(16) in the database
#define DB_UNIQUE_ID_LEN 16

#define PRIV_REG_CONTROLLER 1
#define PRIV_REG_GATEWAY    2

int db_connect();
void db_disconnect();
int db_query(const char* format, ...);

int db_check_privilege(const char *node_id, int priv);
int db_grant_privilege(const char *node_id, int priv);
int db_add_access_request(int priv, const char *node_id, const char *src_ip, int result);

#endif //_DATABASE_H_

