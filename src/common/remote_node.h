#ifndef _REMOTE_NODE_H_
#define _REMOTE_NODE_H_

#include <stdint.h>
#include <time.h>
#include <openssl/sha.h>

#include "ipaddr.h"
#include "uthash.h"
#include "config.h"

struct interface;

struct remote_node {
    int state;

    ipaddr_t        private_ip;
    unsigned short  unique_id;

    uint32_t        global_seq;
    uint32_t*       rec_seq_buffer;

    time_t          creation_time;
    time_t          last_ping_time;
    time_t          last_bw_time;

    uint8_t         private_key[SHA256_DIGEST_LENGTH];

    unsigned int        active_interfaces;
    struct interface*   head_interface;

    // The following are for the database:
    time_t   last_gps_time;
    unsigned last_gps_row_id;

    int cchan_updates;

    UT_hash_handle      hh_id;
    char hash[NODE_HASH_SIZE+1];
};

struct remote_node* alloc_remote_node();
void add_remote_node(struct remote_node* gw);

struct remote_node* lookup_remote_node_by_id(unsigned short id);
struct remote_node* lookup_remote_node_by_ip(ipaddr_t private_ip);

extern struct remote_node* remote_node_id_hash;

#endif //_REMOTE_NODE_H_

