#ifndef _LEASE_H_
#define _LEASE_H_

#include <libconfig.h>
#include <stdint.h>
#include <time.h>
#include <linux/if_ether.h>

#include "uthash.h"

struct lease {
    uint8_t     hw_addr[ETH_ALEN];
    uint32_t    ip;
    time_t      start;
    time_t      end;

    // managed by utlist and uthash
    struct lease*   next;
    struct lease*   prev;
    UT_hash_handle  hh_ip;
    UT_hash_handle  hh_hw;
};

int read_lease_config(const config_t* config);
const struct lease* grant_lease(const uint8_t* hw_addr, unsigned int hw_addr_len);
void remove_stale_leases();

#endif //_LEASE_H_

