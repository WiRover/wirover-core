/*
 * flowTable.h
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <linux/tcp.h>
#include <linux/ip.h>
#include <time.h>

#include "uthash.h"
#include "interface.h"
#include "tunnel.h"

#define SUCCESS 0
#define DUPLICATE_ENTRY 1
#define FILE_ERROR 2

#define MAX_ALG_NAME_LEN   16

struct flow_entry {
    struct flow_tuple *id;
    time_t last_visit_time;
    UT_hash_handle hh;
    uint16_t remote_node_id;
    uint16_t remote_link_id;
    uint16_t local_link_id;
    int count;
    uint32_t ingress_action;
    uint32_t egress_action;
    char ingress_alg_name[MAX_ALG_NAME_LEN];
    char egress_alg_name[MAX_ALG_NAME_LEN];
};

struct flow_tuple {
    uint8_t net_proto;
    uint32_t dst;
    uint32_t src;
    uint8_t proto;
    uint16_t dst_port;
    uint16_t src_port;
};

int fill_flow_tuple(struct iphdr*, struct tcphdr*, struct flow_tuple*, unsigned short reverse);

struct flow_entry *get_flow_entry(struct flow_tuple *);

int update_flow_entry(struct flow_entry *fe);

int set_flow_table_timeout(int);

//Debug Methods
int dump_flow_table_to_file(const char *filename);
void print_flow_entry(struct flow_entry *fe);
void print_flow_table();

#endif //FLOW_TABLE_H

