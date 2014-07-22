/*
 * flowTable.c
 */
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "debug.h"

#include "flow_table.h"
#include "uthash.h"
#include "tunnel.h"
#include "policyTable.h"

#define TIME_BUFFER_SIZE 1024
#define TIME_BETWEEN_EXPIRATION_CHECKS 5

struct flow_entry *flow_table = NULL;
int flow_table_timeout = 10;
time_t last_expiration_check = 0;


int fill_flow_tuple(struct iphdr* ip_hdr, struct tcphdr* tcp_hdr, struct flow_tuple* ft, unsigned short reverse) {
    memset(ft, 0, sizeof(struct flow_tuple));
    ft->net_proto = ip_hdr->version;
    ft->dAddr = reverse ? ip_hdr->saddr : ip_hdr->daddr;
    ft->sAddr = reverse ? ip_hdr->daddr : ip_hdr->saddr;
    ft->proto = ip_hdr->protocol;
    if(ft->proto == 6 || ft->proto == 17){
        ft->dPort = reverse ? tcp_hdr->source : tcp_hdr->dest;
        ft->sPort = reverse ? tcp_hdr->dest : tcp_hdr->source;
    }

    return 0;
}

struct flow_entry *add_entry(struct flow_tuple* entry) {
    struct flow_entry *fe;

    struct flow_tuple *newKey = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
    memset(newKey, 0, sizeof(struct flow_tuple));
    memcpy(newKey, entry, sizeof(struct flow_tuple));
    HASH_FIND(hh, flow_table, newKey, sizeof(struct flow_tuple), fe);
    if(fe == NULL) {
        fe = (struct flow_entry *) malloc(sizeof(struct flow_entry));
        memset(fe, 0, sizeof(struct flow_entry));
        fe->id = newKey;

        fe->last_visit_time = time(NULL);
        HASH_ADD_KEYPTR(hh, flow_table, newKey, sizeof(struct flow_tuple), fe);
        return fe;
    }

    free(newKey);
    return NULL;
}

struct flow_entry *get_flow_entry(struct flow_tuple *ft) {
    struct flow_entry *fe;

    HASH_FIND(hh, flow_table, ft, sizeof(struct flow_tuple), fe);
    if(fe == NULL) {
        struct policy_entry *pd = malloc(sizeof(struct policy_entry));
        getMatch(ft, pd, EGRESS);

        fe = add_entry(ft);
        if(fe == NULL) { return NULL; }
        fe->action = pd->action;
        fe->type = pd->type;
        strcpy(fe->alg_name, pd->alg_name);

        free(pd);
    }
    fe->last_visit_time = time(NULL);

    return fe;
} 

void expiration_time_check() {
    struct flow_entry *current_key, *tmp;

    HASH_ITER(hh, flow_table, current_key, tmp) {
        if(time(NULL) - current_key->last_visit_time > flow_table_timeout) {
            HASH_DEL(flow_table, current_key);
            free(current_key);
        }
    }
}

//Updates an entry and expires old entries in the flow table
int update_flow_entry(struct flow_entry *fe) {

    fe->count++;

    if(last_expiration_check == 0) {
        last_expiration_check = time(NULL);
    }
    if(time(NULL) - last_expiration_check > TIME_BETWEEN_EXPIRATION_CHECKS) {
        expiration_time_check();
        last_expiration_check = time(NULL);
    }

    return SUCCESS;
}


int set_flow_table_timeout(int value) {
    flow_table_timeout = value;

    return 0;
}



//All methods below here are for debugging purposes
void print_flow_entry(struct flow_entry *fe) {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &fe->id->sAddr,src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &fe->id->dAddr,dst_ip, INET6_ADDRSTRLEN);
    DEBUG_MSG("%s:%d -> %s:%d Proto: %d Action: %d node_id: %d link_id: %d hits: %d",
        src_ip, fe->id->sPort, dst_ip, fe->id->dPort,
        fe->id->proto, fe->action, fe->node_id, fe->link_id, fe->count
    );
}

void print_flow_table() {
    struct flow_entry *current_key, *tmp;
    HASH_ITER(hh, flow_table, current_key, tmp) {
        print_flow_entry(current_key);
    }
}


int record_message_to_file(char * file_name, char * msg) {
    FILE *ofp;
    ofp = fopen(file_name, "a");
    if (ofp == NULL) {
        ERROR_MSG("fopen() Failed");
        return FILE_ERROR;
    }

    struct timeval now;
    struct tm nowTm;

    gettimeofday(&now, NULL);
    localtime_r(&now.tv_sec, &nowTm);

    char buff[MAX_DEBUG_LEN];
    char *pbuff = buff;

    snprintf(pbuff, sizeof(buff), "%02d/%02d/%04d %02d:%02d:%02d.%06d",
            nowTm.tm_mon + 1, nowTm.tm_mday, nowTm.tm_year + 1900,
            nowTm.tm_hour, nowTm.tm_min, nowTm.tm_sec, (int)now.tv_usec);

    fprintf(ofp, "%s -- MSG: %s\n", pbuff, msg);

    fclose(ofp);

    return SUCCESS;
}


int record_data_to_file(char * file_name, 
                        struct flow_tuple *ft, struct flow_entry *ftd) {
    FILE *ofp;
    ofp = fopen(file_name, "a");
    if (ofp == NULL) {
        ERROR_MSG("fopen() Failed");
        return FILE_ERROR;
    }

    struct timeval now;
    struct tm nowTm;

    gettimeofday(&now, NULL);
    localtime_r(&now.tv_sec, &nowTm);

    char buff[MAX_DEBUG_LEN];
    char *pbuff = buff;

    snprintf(pbuff, sizeof(buff), "%02d/%02d/%04d %02d:%02d:%02d.%06d",
            nowTm.tm_mon + 1, nowTm.tm_mday, nowTm.tm_year + 1900,
            nowTm.tm_hour, nowTm.tm_min, nowTm.tm_sec, (int)now.tv_usec);

    char sAddrString[20];
    char dAddrString[20];

    strcpy(sAddrString, inet_ntoa(*(struct in_addr*)&ft->sAddr));
    strcpy(dAddrString, inet_ntoa(*(struct in_addr*)&ft->dAddr));

    //fprintf(ofp, "%s -- THE COUNT IS: %d FROM: %" PRIu32 " TO: %" PRIu32 " PORTFROM: %" PRIu16 " PORTTO: %" PRIu16 ", NETPROTO: %" PRIu8 ", PROTO: %" PRIu8 "\n",
            //pbuff, ftd->count, ft->sAddr, ft->dAddr, ft->sPort, ft->dPort, ft->net_proto, ft->proto);

    fprintf(ofp, "%s -- THE COUNT IS: %d FROM: %s TO: %s PORTFROM: %" PRIu16 " PORTTO: %" PRIu16 " NETPROTO: %" PRIu8 " PROTO: %" PRIu8 "\n",
            pbuff, ftd->count, sAddrString, dAddrString, ft->sPort, ft->dPort, ft->net_proto, ft->proto);

    fclose(ofp);

    return SUCCESS;
}
