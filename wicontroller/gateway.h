#ifndef _GATEWAY_H_
#define _GATEWAY_H_

#include <stdint.h>
#include <time.h>

#include "ipaddr.h"
#include "uthash.h"

struct interface;

struct gateway {
    ipaddr_t       private_ip;
    unsigned short unique_id;

    time_t  creation_time;
    int32_t secret_word;
    time_t  last_ping_time;

    unsigned int        active_interfaces;
    struct interface*   head_interface;

    UT_hash_handle      hh_id;
};

struct gateway* alloc_gateway();
void add_gateway(struct gateway* gw);

struct gateway* lookup_gateway_by_id(unsigned short id);

extern struct gateway* gateway_id_hash;

#endif //_GATEWAY_H_

