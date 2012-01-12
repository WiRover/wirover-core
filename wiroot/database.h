#ifndef _DATABASE_H_
#define _DATABASE_H_

#define DB_HOST "127.0.0.1"
#define DB_USER "wirover"
#define DB_PASS ""
#define DB_NAME "gateways"

#define MAX_QUERY_LEN 1024

// The unique id is stored as a char(16) in the database
#define DB_UNIQUE_ID_LEN 16

int db_connect();
void db_disconnect();
int db_query(const char* format, ...);

unsigned short db_get_unique_id(const char* hwaddr);

#endif //_DATABASE_H_

