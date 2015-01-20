#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>
//#include <mysql/my_global.h>

#include "configuration.h"
#include "database.h"
#include "debug.h"
#include "rootchan.h"

static MYSQL* database = 0;

int db_connect()
{
    int result;

    const config_t *config = get_config();
    const char *db_host = DEFAULT_MYSQL_HOST;
    const char *db_user = DEFAULT_MYSQL_USER;
    const char *db_pass = DEFAULT_MYSQL_PASSWORD;
    const char *db_name = DEFAULT_MYSQL_DATABASE;

    if(database) {
        return 0;
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
        goto err_out;
    }

    if(!mysql_real_connect(database, db_host, db_user, db_pass, db_name, 0, 0, 0)) {
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
 * Check if the node should be granted the requested privilege.
 *
 * Returns a positive ID if the privilege is to be granted, 0 if not, or
 * negative if there is an error.
 */
int db_check_privilege(const char *node_id, int priv)
{
    int result;
    int id = 0;

    int node_id_len = strlen(node_id);
    char *node_id_esc = malloc(2 * node_id_len + 1);
    if(!node_id_esc)
        return -1;
    mysql_real_escape_string(database, node_id_esc, node_id, node_id_len);

    result = db_query("select id, controller_priv, gateway_priv from nodes where node_id='%s' limit 1", node_id_esc);
    free(node_id_esc);

    if(result < 0)
        return -1;

    MYSQL_RES *qr = mysql_store_result(database);
    if(!qr) {
        DEBUG_MSG("mysql_store_result failed - %s", mysql_error(database));
        return -1;
    }

    MYSQL_ROW row = mysql_fetch_row(qr);
    if(row) {
        if((priv == PRIV_REG_CONTROLLER && atoi(row[1]) > 0) ||
                (priv == PRIV_REG_GATEWAY && atoi(row[2]) > 0))
            id = atoi(row[0]);
    }

    mysql_free_result(qr);
    return id;
}

/*
 * Grant a privilege to the given node_id.
 *
 * Returns a positive ID if the privilege is to be granted, 0 if not, or
 * negative if there is an error.
 */
int db_grant_privilege(const char *node_id, int priv, const char *pub_key)
{
    int result;
    int id = 0;

    int node_id_len = strlen(node_id);
    char *node_id_esc = malloc(2 * node_id_len + 1);
    if(!node_id_esc)
        return -1;
    mysql_real_escape_string(database, node_id_esc, node_id, node_id_len);

    const char *priv_str = (priv == PRIV_REG_CONTROLLER) ?
        "controller_priv" : "gateway_priv";

    result = db_query("insert into nodes (node_id, %s, public_key) values ('%s', 1, '%s') on duplicate key update %s=1, public_key = '%s'",
            priv_str, node_id_esc, pub_key, priv_str, pub_key);
    free(node_id_esc);

    if(result <= 0)
        return -1;

    id = mysql_insert_id(database);

    return id;
}

/*
 * Grant a privilege to the given node_id.
 *
 * Returns a positive ID if the privilege is to be granted, 0 if not, or
 * negative if there is an error.
 */
int db_update_pub_key(const char *node_id, const char *pub_key)
{
    int result;
    int id = 0;

    int node_id_len = strlen(node_id);
    char *node_id_esc = malloc(2 * node_id_len + 1);
    if(!node_id_esc)
        return -1;
    mysql_real_escape_string(database, node_id_esc, node_id, node_id_len);

    result = db_query("update nodes set public_key = '%s' where node_id = '%s'",
            pub_key, node_id);
    free(node_id_esc);

    if(result < 0)
        return -1;

    id = mysql_insert_id(database);

    return id;
}
int db_get_pub_key(int remote_id, char *pub_key)
{
    int result;

    result = db_query("select public_key from nodes where id=%d limit 1", remote_id);

    if(result < 0)
        return FAILURE;

    MYSQL_RES *qr = mysql_store_result(database);
    if(!qr) {
        DEBUG_MSG("mysql_store_result failed - %s", mysql_error(database));
        return FAILURE;
    }

    MYSQL_ROW row = mysql_fetch_row(qr);
    if(row) {
        memcpy(pub_key, row[0], strlen(row[0]));
    }

    mysql_free_result(qr);
    return strlen(pub_key);
}

/*
 * Record an access request so that a network admin can approve it.
 */
int db_add_access_request(int priv, const char *node_id, const char *src_ip, int result)
{
    const char *type;
    switch(priv) {
        case PRIV_REG_CONTROLLER:
            type = "CONTROLLER";
            break;
        case PRIV_REG_GATEWAY:
            type = "GATEWAY";
            break;
        default:
            DEBUG_MSG("Unrecognized access type: %d", priv);
            return -1;
    }

    const char *result_str;
    switch(result) {
        case RCHAN_RESULT_SUCCESS:
            result_str = "SUCCESS";
            break;
        case RCHAN_RESULT_DENIED:
            result_str = "DENIED";
            break;
        default:
            DEBUG_MSG("Unrecognized access result: %d", result);
            return -1;
    }

    int node_id_len = strlen(node_id);
    char *node_id_esc = malloc(2 * node_id_len + 1);
    if(!node_id_esc)
        return -1;
    mysql_real_escape_string(database, node_id_esc, node_id, node_id_len);

    int ret = db_query("insert into access_requests (type, result, node_id, src_ip) values ('%s', '%s', '%s', '%s')", 
            type, result_str, node_id_esc, src_ip);
    free(node_id_esc);

    if(ret < 0)
        return -1;

    return 0;
}

