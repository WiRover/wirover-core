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
#include "policy_table.h"

#define TIME_BUFFER_SIZE 1024
#define TIME_BETWEEN_EXPIRATION_CHECKS 5

struct flow_entry *flow_table = NULL;
int flow_table_timeout = 10;
time_t last_expiration_check = 0;


int fill_flow_tuple(char *packet, struct flow_tuple* ft, unsigned short ingress) {
    struct iphdr *ip_hdr = (struct iphdr *)(packet);
    struct tcphdr   *tcp_hdr = (struct tcphdr *)(packet + (ip_hdr->ihl * 4));

    memset(ft, 0, sizeof(struct flow_tuple));
    ft->ingress = ingress;
    ft->net_proto = ip_hdr->version;
    ft->remote = ingress ? ip_hdr->saddr : ip_hdr->daddr;
    ft->local = ingress ? ip_hdr->daddr : ip_hdr->saddr;
    ft->proto = ip_hdr->protocol;
    if(ft->proto == 6 || ft->proto == 17){
        ft->remote_port = ingress ? tcp_hdr->source : tcp_hdr->dest;
        ft->local_port = ingress ? tcp_hdr->dest : tcp_hdr->source;
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
        fe = add_entry(ft);
        if(fe == NULL) { return NULL; }
        policy_entry pd;
        memset(&pd, 0, sizeof(policy_entry));
        get_policy_by_tuple(ft,  &pd, ft->ingress ? DIR_INGRESS : DIR_EGRESS);
        fe->action = pd.action;
        fe->rate_limit = pd.rate_limit;
        strcpy(fe->alg_name, pd.alg_name);
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
    char local_ip[INET6_ADDRSTRLEN];
    char remote_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &fe->id->local, local_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &fe->id->remote, remote_ip, INET6_ADDRSTRLEN);
    char * dir_string = fe->id->ingress ? "<-" : "->";
    return snprintf(str, size, "%s:%d %s %s:%d Proto: %d Action: %d remote: %d:%d Local link: %d hits: %d",
        local_ip, ntohs(fe->id->local_port), dir_string, remote_ip, ntohs(fe->id->remote_port),
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
