#ifndef _LEASE_H_
#define _LEASE_H_

#include <libconfig.h>
#include <stdint.h>
#include <time.h>
#include <linux/if_ether.h>

#include "controllers.h"
#include "ipaddr.h"
#include "uthash.h"

#define IPV4_ADDRESS_BITS   32

struct lease {
    int         unique_id;
    ipaddr_t    ip;
    time_t      start;
    time_t      end;

    // managed by utlist and uthash
    struct lease*   next;
    struct lease*   prev;
    UT_hash_handle  hh_ip;
    UT_hash_handle  hh_uid;
};

int read_lease_config(const config_t* config);
const struct lease* grant_gw_lease(int unique_id, struct controller *controller);
const struct lease* grant_controller_lease(int unique_id);
void remove_stale_leases();
uint8_t get_gateway_subnet_size();
uint8_t get_controller_subnet_size();

#endif //_LEASE_H_

