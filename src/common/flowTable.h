/*
 * flowTable.h
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <linux/tcp.h>
#include <linux/ip.h>
#include <time.h>

#include "uthash.h"

#define SUCCESS 0
#define DUPLICATE_ENTRY 1
#define FILE_ERROR 2

#define MAX_ALG_NAME_LEN   16

struct flow_entry {
    struct flow_tuple *id;
    time_t last_visit_time;
    UT_hash_handle hh;

    int count;
    uint32_t action;
    int32_t type;
    char alg_name[MAX_ALG_NAME_LEN];
};

struct flow_tuple {
    uint8_t net_proto;
    uint32_t dAddr;
    uint32_t sAddr;
    uint8_t proto;
    uint16_t dPort;
    uint16_t sPort;
};

int fill_flow_tuple(struct iphdr*, struct tcphdr*, struct flow_tuple*);

struct flow_entry *get_flow_entry(struct flow_tuple *);

int update_flow_table(struct flow_tuple *entry, uint32_t action, int32_t type, char *alg_name);

int set_flow_table_timeout(int);

//Debug Methods
int record_data_to_file(char *, struct flow_tuple *, struct flow_entry *);

int record_message_to_file(char *, char *);

int print_keys();

#endif //FLOW_TABLE_H

