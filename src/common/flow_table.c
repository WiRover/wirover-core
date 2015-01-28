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
#include "packet.h"
#include "policy_table.h"
#include "rate_control.h"
#include "rwlock.h"

#define TIME_BUFFER_SIZE 1024
#define TIME_BETWEEN_EXPIRATION_CHECKS 5

struct flow_entry *flow_table = NULL;
struct rwlock flow_table_lock = RWLOCK_INITIALIZER;
int flow_table_timeout = 10;
time_t last_expiration_check = 0;


int fill_flow_tuple(char *packet, struct flow_tuple* ft, unsigned short ingress) {
    struct iphdr *ip_hdr = (struct iphdr *)(packet);
    struct tcphdr   *tcp_hdr = (struct tcphdr *)(packet + (ip_hdr->ihl * 4));

    memset(ft, 0, sizeof(struct flow_tuple));
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

void fill_flow_entry_data(struct flow_entry_data *fed, policy_entry * pd)
{
    fed->action = pd->action;
    if(pd->rate_limit != 0)
    {
        fed->rate_control = (struct rate_control *)malloc(sizeof(struct rate_control));
        rc_init(fed->rate_control, 10, 20000, pd->rate_limit);

    }
    strcpy(fed->alg_name, pd->alg_name);
}

struct flow_entry *add_entry(struct flow_tuple* tuple, uint8_t owner) {
    struct flow_entry *fe;

    struct flow_tuple *newKey = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
    memset(newKey, 0, sizeof(struct flow_tuple));
    memcpy(newKey, tuple, sizeof(struct flow_tuple));
    HASH_FIND(hh, flow_table, newKey, sizeof(struct flow_tuple), fe);
    if(fe == NULL) {
        fe = (struct flow_entry *) malloc(sizeof(struct flow_entry));
        memset(fe, 0, sizeof(struct flow_entry));
        fe->id = newKey;
        fe->owner = owner;

        policy_entry pd;
        memset(&pd, 0, sizeof(policy_entry));
        get_policy_by_tuple(tuple,  &pd, DIR_EGRESS);
        fill_flow_entry_data(&fe->egress, &pd);
        get_policy_by_tuple(tuple,  &pd, DIR_INGRESS);
        fill_flow_entry_data(&fe->ingress, &pd);

        if((fe->egress.action & POLICY_ACT_MASK) == POLICY_ACT_ENCAP)
        {
            fe->requires_flow_info = 3;
        }

        fe->last_visit_time = time(NULL);
        HASH_ADD_KEYPTR(hh, flow_table, newKey, sizeof(struct flow_tuple), fe);
    }
    return fe;
}

struct flow_entry *get_flow_entry(struct flow_tuple *ft) {
    struct flow_entry *fe;

    HASH_FIND(hh, flow_table, ft, sizeof(struct flow_tuple), fe);
    if(fe == NULL) {
        return NULL;
    }
    fe->last_visit_time = time(NULL);

    return fe;
} 

struct flow_entry *get_flow_table() {
    return flow_table;
}

void free_flow_table() {
    struct flow_entry *current_key, *tmp;

    HASH_ITER(hh, flow_table, current_key, tmp) {
            free_flow_entry(current_key);
    }
}

void free_flow_entry(struct flow_entry * fe) {
    obtain_write_lock(&flow_table_lock);
    HASH_DEL(flow_table, fe);
    free(fe->id);
    while(fe->ingress.packet_queue_head) {
        struct packet * pkt = fe->ingress.packet_queue_head;
        packet_queue_dequeue(&fe->ingress.packet_queue_head);
        free_packet(pkt);
    }
    while(fe->egress.packet_queue_head) {
        struct packet * pkt = fe->egress.packet_queue_head;
        packet_queue_dequeue(&fe->egress.packet_queue_head);
        free_packet(pkt);
    }
    free(fe);
    release_write_lock(&flow_table_lock);
}

void expiration_time_check() {
    struct flow_entry *current_key, *tmp;

    HASH_ITER(hh, flow_table, current_key, tmp) {
        if(time(NULL) - current_key->last_visit_time > flow_table_timeout) {
            free_flow_entry(current_key);
        }
    }
}

//Updates an entry and expires old entries in the flow table
int update_flow_entry(struct flow_entry *fe) {

    if(last_expiration_check == 0) {
        last_expiration_check = time(NULL);
    }
    if(time(NULL) - last_expiration_check > TIME_BETWEEN_EXPIRATION_CHECKS) {
        expiration_time_check();
        last_expiration_check = time(NULL);
    }

    return SUCCESS;
}

void flow_tuple_invert(struct flow_tuple *ft)
{
    int temp;
    temp = ft->local;
    ft->local = ft->remote;
    ft->remote = temp;
    temp = ft->local_port;
    ft->local_port = ft->remote_port;
    ft->remote_port = temp;
}

int set_flow_table_timeout(int value) {
    flow_table_timeout = value;

    return 0;
}

int flow_tuple_to_string(const struct flow_tuple *ft, char *str, int size) {
    char local_ip[INET6_ADDRSTRLEN];
    char remote_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &ft->local, local_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &ft->remote, remote_ip, INET6_ADDRSTRLEN);
    return snprintf(str, size, "%s:%d <-> %s:%d Proto: %d",
        local_ip, ntohs(ft->local_port), remote_ip, ntohs(ft->remote_port),
        ft->proto);

}
int flow_data_to_string(const struct flow_entry_data *fed, char *str, int size) {
    return snprintf(str, size, "Action: %d remote: %d:%d Local link: %d hits: %d",
        fed->action, fed->remote_node_id, fed->remote_link_id, fed->local_link_id, fed->count
    );
}
int flow_entry_to_string(const struct flow_entry *fe, char *str, int size)
{
    char ft_buffer[128];
    char egress_buffer[128];
    char ingress_buffer[128];

    flow_tuple_to_string(fe->id, ft_buffer, sizeof(ft_buffer));
    flow_data_to_string(&fe->ingress, ingress_buffer, sizeof(ingress_buffer));
    flow_data_to_string(&fe->egress, egress_buffer, sizeof(egress_buffer));
    return snprintf(str, size, "%s\n\tIngress: %s\n\tEgress: %s", ft_buffer, ingress_buffer, egress_buffer);
}
//All methods below here are for debugging purposes
void print_flow_tuple(struct flow_tuple *ft) {
    char buffer[128];
    flow_tuple_to_string(ft, buffer, sizeof(buffer));
    DEBUG_MSG("%s\n", buffer);
}
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
    obtain_read_lock(&flow_table_lock);
    HASH_ITER(hh, flow_table, current_key, tmp) {
        flow_entry_to_string(current_key, buffer, sizeof(buffer));
        fprintf(ft_file, "%s\n", buffer);
    }
    release_read_lock(&flow_table_lock);
    fclose(ft_file);
    return SUCCESS;
}
