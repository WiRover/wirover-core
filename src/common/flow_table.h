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

struct flow_entry {
    struct flow_tuple *id;
    time_t last_visit_time;
    UT_hash_handle hh;
    uint16_t remote_node_id;
    uint16_t remote_link_id;
    uint16_t local_link_id;
    int count;
    uint32_t action;
    char alg_name[MAX_ALG_NAME_LEN];
    //Count of packets to include flow info in
    uint8_t requires_flow_info;

    // Rate limiting and packet queueing
    struct rate_control * rate_control;
    struct packet * packet_queue_head;
    struct packet * packet_queue_tail;
};

struct flow_tuple {
    uint8_t ingress;
    uint8_t net_proto;
    uint32_t remote;
    uint32_t local;
    uint8_t proto;
    uint16_t remote_port;
    uint16_t local_port;
};

int fill_flow_tuple(char *packet, struct flow_tuple* ft, unsigned short ingress);

struct flow_entry *add_entry(struct flow_tuple* tuple);
struct flow_entry *get_flow_entry(struct flow_tuple *);
struct flow_entry *get_flow_table();

int update_flow_entry(struct flow_entry *fe);

int set_flow_table_timeout(int);
void print_flow_tuple(struct flow_tuple *);
void free_flow_entry(struct flow_entry * fe);
void free_flow_table();

//Debug Methods
int dump_flow_table_to_file(const char *filename);
void print_flow_entry(struct flow_entry *fe);
void print_flow_table();

#endif //FLOW_TABLE_H

