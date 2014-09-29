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
    }
    return fe;
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
            free(current_key->id);
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


int flow_entry_to_string(const struct flow_entry *fe, char *str, int size) {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &fe->id->sAddr,src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &fe->id->dAddr,dst_ip, INET6_ADDRSTRLEN);
    return snprintf(str, size, "%s:%d -> %s:%d Proto: %d Action: %d remote: %d:%d Local link: %d hits: %d",
        src_ip, ntohs(fe->id->sPort), dst_ip, ntohs(fe->id->dPort),
        fe->id->proto, fe->action, fe->remote_node_id, fe->remote_link_id, fe->local_link_id, fe->count
    );
}
//All methods below here are for debugging purposes
void print_flow_entry(struct flow_entry *fe) {
    char buffer[128];
    flow_entry_to_string(fe, buffer, sizeof(buffer));
    DEBUG_MSG("%s\n", buffer);
}

void print_flow_table() {
    struct flow_entry *current_key, *tmp;
    HASH_ITER(hh, flow_table, current_key, tmp) {
        print_flow_entry(current_key);
    }
}


int dump_flow_table_to_file(const char *filename)
{
    FILE *ft_file = fopen(filename, "w");
    if(ft_file == NULL)
        return FAILURE;
    char buffer[128];
    struct flow_entry *current_key, *tmp;
    HASH_ITER(hh, flow_table, current_key, tmp) {
        flow_entry_to_string(current_key, buffer, sizeof(buffer));
        fprintf(ft_file, "%s\n", buffer);
    }
    fclose(ft_file);
    return SUCCESS;
}
