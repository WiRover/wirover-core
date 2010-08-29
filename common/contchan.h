#ifndef _CONTCHAN_H_
#define _CONTCHAN_H_

#include <stdint.h>
#include <linux/if_ether.h>

// Control channel packet types
#define CONTCHAN_LEASE_REQUEST          0x01
#define CONTCHAN_LEASE_RESPONSE         0x02

struct contchan_lease_request {
    uint8_t     type;
    uint8_t     hw_addr[ETH_ALEN];
} __attribute__((__packed__));

struct contchan_lease_response {
    uint8_t     type;
    uint32_t    priv_ip;
    uint32_t    lease_time;
} __attribute__((__packed__));

#endif //_CONTCHAN_H_

