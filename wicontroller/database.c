#define _BSD_SOURCE /* Required for be64toh */

#include <arpa/inet.h>
#include <ctype.h>
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
#include "dbq.h"
#include "debug.h"
#include "gateway.h"
#include "interface.h"
#include "ping.h"
#include "timing.h"

static MYSQL* database = 0;
char cont_hash[NODE_HASH_SIZE + 1];
char hostname[1024];
int cont_id;
int verify_hash(char* hash)
{
    for(int i = 0; i < NODE_HASH_SIZE; i++){
        if(!isalnum(hash[i])) { return 0; }
    }
    if(hash[NODE_HASH_SIZE]!=0) { return 0; }
    return 1;
}

int init_database()
{
    FILE *fp = fopen("/etc/wirover.d/node_id","r");
    fscanf(fp,"%s",cont_hash);
    fclose(fp);

    fp = fopen("/etc/hostname","r");
    fscanf(fp,"%s",hostname);
    fclose(fp);
    
    if(!verify_hash(cont_hash)) {
         DEBUG_MSG("Controller's hash is invalid");
         return -1;
    }
    pthread_t db_write_thr;

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
        DEBUG_MSG(db_host);
    }
    init_dbq();
    database = mysql_init(0);
    if(!database) {
        DEBUG_MSG("mysql_init() failed");
        return -1;
    }
    
    const my_bool yes = 1;
    if(mysql_options(database, MYSQL_OPT_RECONNECT, &yes) != 0) {
        DEBUG_MSG("Warning: mysql_option failed");
    }
    if(!mysql_real_connect(database, db_host, db_user, db_pass, db_name, 0, 0, 0)) {
        DEBUG_MSG("mysql_real_connect() failed");
        mysql_close(database);
        database = 0;
        return -1;
    }

    char query[1024];
    snprintf(query,1024,"insert ignore into controllers (hash,name) values ('%s','%s') on duplicate key update name = '%s'",cont_hash,hostname,hostname);
    int res = mysql_query(database, query);
    if(res != 0){
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
        return -1;
    }
    snprintf(query,1024,"SELECT id from controllers where hash = '%s'",cont_hash);
    res = mysql_query(database, query);
    if(res != 0){
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
        return -1;
    }
    MYSQL_RES *result = mysql_store_result(database);
    MYSQL_ROW row = mysql_fetch_row(result);
    mysql_free_result(result);
    if(!row){
        DEBUG_MSG("Controller not present in database");
        return -1;
    }
    cont_id = atoi(row[0]);

    if(pthread_create(&db_write_thr,NULL,&db_write_loop,NULL))
        DEBUG_MSG("Error: could not create database write thread");
    return 0;
}

void close_database()
{
    mysql_close(database);
    database = 0;
}
void db_write_loop()
{
  dbqreq* req;
  while(1){
    req = dbq_dequeue();
    if(!verify_hash(req->hash)) {
        DEBUG_MSG("Database request enqueued with invalid node hash");
        goto continue_free;
    }
    int len = 0;
    char query[1024];
    MYSQL_RES *result;
    MYSQL_ROW row;

    /*Add the gateway if it isn't already in the table*/
    snprintf(query,1024,"INSERT ignore into gateways (hash,conid) values ('%s','%d') on duplicate key update conid = '%d'",req->hash,cont_id,cont_id);
    int res = mysql_query(database,query);
    if(res != 0){ 
      DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
      goto continue_free;
    }

    /*Convert the hash into the gateways node id*/
    snprintf(query,1024,"SELECT id from gateways where hash = '%s'",req->hash);
    res = mysql_query(database, query);
    if(res != 0){
      DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
      goto continue_free;
    }
    result = mysql_store_result(database);
    row = mysql_fetch_row(result);
    mysql_free_result(result);
    if(!row){
      DEBUG_MSG("Error finding gateway");
      goto continue_free;
    }
    int gwid = atoi(row[0]);

    /*Insert the node id into the query*/
    len = snprintf(query,1024,req->query,gwid);
    res = mysql_real_query(database, query, len);
    if(res != 0) {
        DEBUG_MSG("mysql_query() failed: %s", mysql_error(database));
        goto continue_free;
    }

    /* Update the last_gps_id for the gateway. */
    if(req->gps_req){
        DEBUG_MSG("Last query before gps: %s",query);
        int gps_row_id = mysql_insert_id(database);
        DEBUG_MSG("Last gps id = %d",gps_row_id);
        len = snprintf(req->query, 1024,
            "update gateways set last_gps_id=%u where id=%hu",
            gps_row_id, gwid);
        res = mysql_real_query(database, req->query, len);
    }
continue_free:
    free(req);
  }
}
int db_update_gateway(const struct gateway *gw, int state_change)
{
    if(!database)
        return -1;


    dbqreq* req = (dbqreq*)malloc(sizeof(dbqreq));
    dbqreq* state_req;
    if(gw->state == ACTIVE) {
        char priv_ip[INET6_ADDRSTRLEN];
        ipaddr_to_string(&gw->private_ip, priv_ip, sizeof(priv_ip));

        if(state_change) {
            snprintf(req->query, 1024,
                    "update gateways set state=%d, eventtime=NOW(), private_ip='%s' where id='%s'",
                    gw->state, priv_ip,"%hu");
        } else {
            snprintf(req->query, 1024,
                    "update gateways set state=%d, private_ip='%s' where id='%s'",
                    gw->state, priv_ip,"%hu");
        }
    } else {
        if(state_change) {
            
            snprintf(req->query, 1024,
                    "update gateways set state=%d, eventtime=NOW(), private_ip=NULL where id='%s'",
                    gw->state,"%hu");
        } else {
            snprintf(req->query, 1024,
                    "update gateways set state=%d, private_ip=NULL where id='%s'",
                    gw->state,"%hu");
        }
    }
    if(state_change) {
        state_req = (dbqreq*)malloc(sizeof(dbqreq));
        snprintf(state_req->query, 1024,
                    "insert into state_log (node_id, new_state) values ('%s', '%d')",
                    "%hu",gw->state);
        state_req->gps_req = 0;
        state_req->gwid = gw->unique_id;
        memcpy(state_req->hash,gw->hash,sizeof(gw->hash));
        dbq_enqueue(state_req);   
    }
    req->gps_req = 0;
    req->gwid = gw->unique_id;
    memcpy(req->hash,gw->hash,sizeof(gw->hash));
    dbq_enqueue(req);

    return 0;
}

int db_update_link(const struct gateway *gw, const struct interface *ife)
{
    if(!database)
        return -1;

    // Do not update database if link's network name is unknown
    if(!ife->network[0])
        return 0;

    char pub_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &ife->public_ip, pub_ip, sizeof(pub_ip));

    dbqreq* req = (dbqreq*)malloc(sizeof(dbqreq));
    snprintf(req->query, 1024,
            "insert into links (gatewayid, network, ip, avg_bw_down, avg_bw_up, "
            "avg_rtt, state, updated) values "
            "(%s, '%s', '%s', '%f', '%f', '%f', %d, NOW()) "
            "on duplicate key update ip='%s', avg_bw_down='%f', avg_bw_up='%f', "
            "avg_rtt='%f', state=%d, updated=NOW()",
            "%hu", ife->network, pub_ip, 
            ife->avg_downlink_bw, ife->avg_uplink_bw, ife->avg_rtt, ife->state,
            pub_ip, ife->avg_downlink_bw, ife->avg_uplink_bw,
            ife->avg_rtt, ife->state);
    req->gps_req = 0;
    req->gwid = gw->unique_id;
    memcpy(req->hash,gw->hash,sizeof(gw->hash));
    dbq_enqueue(req);

    return 0;
}

int db_update_gps(struct gateway *gw, const struct gps_payload *gps)
{
    if(!database)
        return -1;

    /*This won't work now
    const time_t now = time(0);
    if(now == gw->last_gps_time) {
        // Avoid adding a duplicate.
        return -1;
    }*/

    dbqreq* req = (dbqreq*)malloc(sizeof(dbqreq));
    snprintf(req->query, 1024,
            "insert into gps (node_id, status, latitude, longitude,"
            "altitude, track, speed, climb) values ('%s', '%d', '%f',"
            "'%f', '%f', '%f', '%f', '%f')",
            "%hu", gps->status, gps->latitude, gps->longitude,
            gps->altitude, gps->track, gps->speed, gps->climb);
    req->gps_req = 1;
    req->gwid = gw->unique_id;
    memcpy(req->hash,gw->hash,sizeof(gw->hash));
    dbq_enqueue(req);
    return 0;

}

int db_update_pings(const struct gateway *gw, const struct interface *ife, int rtt)
{
    if(!database)
        return -1;

    dbqreq* req = (dbqreq*)malloc(sizeof(dbqreq));

    snprintf(req->query, 1024,
            "insert into pings (node_id, network, gps_id, rtt)"
            "select gateways.id,"
            "       '%s',"
            "       IF(not EXISTS(select 1 from gps where id = last_gps_id) or last_gps_id = NULL or TIMESTAMPDIFF(SECOND,gps.time,NOW())>5,NULL,last_gps_id),"
            "       %d "
            "from gateways left join gps on last_gps_id = gps.id where gateways.id = '%s'",
            ife->network, rtt,"%hu");
 
    req->gwid = gw->unique_id;
    req->gps_req = 0;
    memcpy(req->hash,gw->hash,sizeof(gw->hash));

    dbq_enqueue(req);
    return 0;
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


    dbqreq* req = (dbqreq*)malloc(sizeof(dbqreq));
    snprintf(req->query, 1024,
            "insert into passive (node_id, network, time, interval_len, "
            "bytes_tx, bytes_rx, rate_down, rate_up, packets_tx, packets_rx) values "
            "('%s', '%s', NOW(), %ld, %llu, %llu, '%f', '%f', %u, %u)",
            "%hu", ife->network, time_diff,
            bytes_tx_diff, bytes_rx_diff,
            rate_down, rate_up,
            packets_tx_diff, packets_rx_diff);
    req->gwid = gw->unique_id;
    req->gps_req = 0;
    memcpy(req->hash,gw->hash,sizeof(gw->hash));

    dbq_enqueue(req);
    
    req = (dbqreq*)malloc(sizeof(dbqreq));
    snprintf(req->query, 1024,
            "update links set bytes_tx=bytes_tx+%llu, bytes_rx=bytes_rx+%llu, "
            "month_tx=month_tx+%llu, month_rx=month_rx+%llu, updated=NOW() "
            "where gatewayid='%s' and network='%s'",
            bytes_tx_diff, bytes_rx_diff, bytes_tx_diff, bytes_rx_diff,
            "%hu", ife->network);
    req->gwid = gw->unique_id;
    req->gps_req = 0;
    memcpy(req->hash,gw->hash,sizeof(gw->hash));

    dbq_enqueue(req);

    return 0;
}

int db_update_bandwidth(const struct gateway *gw, const struct interface *ife, 
                int type, double bw_down, double bw_up)
{
    if(!database)
        return -1;

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

    dbqreq *req = (dbqreq*)malloc(sizeof(dbqreq));
    snprintf(req->query, 1024,
            "insert into bandwidth (node_id, network, gps_id, bw_down, bw_up, type) "
            "select gateways.id,'%s',"
            "       IF(last_gps_id = NULL or TIMESTAMPDIFF(SECOND,gps.time,NOW())>5,NULL,last_gps_id),"
            "       '%f', '%f', %s "
            "from gateways left join gps on last_gps_id = gps.id where gateways.id = '%s'",
                ife->network, bw_down, bw_up, type_str,"%hu");
    req->gps_req = 0;
    req->gwid = gw->unique_id;
    memcpy(req->hash,gw->hash,sizeof(gw->hash));

    dbq_enqueue(req);
    return 0;
}
