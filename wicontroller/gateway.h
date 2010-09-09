#ifndef _GATEWAY_H_
#define _GATEWAY_H_

#include <stdint.h>
#include <time.h>
#include "uthash.h"

struct interface;

struct gateway {
    uint32_t            private_ip; //IP is stored in network byte order
    unsigned short      unique_id;

    time_t              creation_time;

    unsigned int        active_interfaces;
    struct interface*   head_interface;

    UT_hash_handle      hh_id;
};

struct gateway* alloc_gateway();
void add_gateway(struct gateway* gw);

struct gateway* lookup_gateway_by_id(unsigned short id);

#endif //_GATEWAY_H_

