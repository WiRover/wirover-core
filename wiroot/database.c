#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>
//#include <mysql/my_global.h>

#include "database.h"
#include "debug.h"

static MYSQL* database = 0;

int db_connect()
{
    int result;

    if(database) {
        return 0;
    }

    database = mysql_init(0);
    if(!database) {
        DEBUG_MSG("mysql_init() failed");
        goto err_out;
    }

    if(!mysql_real_connect(database, DB_HOST, DB_USER, DB_PASS, DB_NAME,
                                0, 0, 0)) {
        DEBUG_MSG("mysql_real_connect() failed: %s", mysql_error(database));
        goto close_and_err_out;
    }
    
    my_bool yes = 1;
    result = mysql_options(database, MYSQL_OPT_RECONNECT, &yes);
    if(result != 0) {
        DEBUG_MSG("Warning: mysql_option() failed: %s", mysql_error(database));
    }

    return 0;

close_and_err_out:
    mysql_close(database);
    database = NULL;
err_out:
    return -1;
}

void db_disconnect()
{
    if(database) {
        mysql_close(database);
        database = 0;
    }
}

/*
 * DB QUERY
 *
 * Performs a MYSQL query on the database.  The syntax is the same as printf.
 *
 * Returns 0 on success or -1 on failure.
 */
int db_query(const char* format, ...)
{
    va_list args;
    char query[MAX_QUERY_LEN];
    int len;
    int result;

    va_start(args, format);
    len = vsnprintf(query, sizeof(query), format, args);
    va_end(args);

    if(len >= sizeof(query)) {
        DEBUG_MSG("vsnprintf overflow");
        return -1;
    }

    result = mysql_real_query(database, query, len);
    if(result != 0) {
        DEBUG_MSG("mysql_query failed - %s", mysql_error(database));
        return -1;
    }
        
    return 0;
}

/*
 * DB GET UNIQUEID
 */
unsigned short db_get_unique_id(const char* hwaddr)
{
    int result;
    unsigned short unique_id = 0;

    result = db_query("select id from uniqueid where hwaddr='%s' limit 1", hwaddr);
    if(result == -1) {
        return 0;
    }

    MYSQL_RES* qr = mysql_store_result(database);
    if(!qr) {
        DEBUG_MSG("mysql_store_result failed - %s", mysql_error(database));
        return 0;
    }
    
    MYSQL_ROW row = mysql_fetch_row(qr);
    
    if(row) {
        unique_id = atoi(row[0]);
        
    } else {
        // Make an entry for the node
        result = db_query("insert into uniqueid (hwaddr) values ('%s')", hwaddr);
        if(result == 0) {
            unique_id = mysql_insert_id(database);
        }
    }

    mysql_free_result(qr);
    return unique_id;
}




