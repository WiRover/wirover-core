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
#include "packet.h"

#define MAX_ALG_NAME_LEN   16

struct flow_entry_data {
    uint16_t remote_node_id;
    uint16_t remote_link_id;
    uint16_t local_link_id;
    int count;
    uint8_t action;
    uint8_t link_select;

    // Rate limiting and packet queueing
    struct rate_control * rate_control;
};

struct flow_entry {
    struct flow_tuple *id;
    time_t last_visit_time;
    UT_hash_handle hh;
    uint8_t owner;
    //Count of packets to include flow info in
    uint8_t requires_flow_info;
    struct flow_entry_data egress;
    struct flow_entry_data ingress;
};

struct flow_tuple {
    uint8_t net_proto;
    uint32_t remote;
    uint32_t local;
    uint8_t proto;
    uint16_t remote_port;
    uint16_t local_port;
} __attribute__((__packed__));

struct tunhdr_flow_info {
    uint8_t     action;
    uint8_t     link_select;
    __be32      rate_limit;
    uint16_t    local_link_id;
    uint16_t    remote_link_id;
} __attribute__((__packed__));

int fill_flow_tuple(char *packet, struct flow_tuple* ft, unsigned short ingress);

struct flow_entry *add_entry(struct flow_tuple* tuple, uint8_t owner);
struct flow_entry *add_entry_info(struct packet *pkt, int remote_node_id);
struct flow_entry *get_flow_entry(struct flow_tuple *);
struct flow_entry *get_flow_table();

void hton_flow_tuple(struct flow_tuple *src, struct flow_tuple *dst);
void ntoh_flow_tuple(struct flow_tuple *src, struct flow_tuple *dst);

void fill_flow_info(struct flow_entry *fe, struct packet *dst);

int update_flow_entry(struct flow_entry *fe);
void flow_tuple_invert(struct flow_tuple *ft);

void print_flow_tuple(struct flow_tuple *);
void free_flow_entry(struct flow_entry * fe);
void free_flow_table();

//Debug Methods
int dump_flow_table_to_file(const char *filename);
void print_flow_entry(struct flow_entry *fe);
void print_flow_table();

#endif //FLOW_TABLE_H

