#ifndef _CONTCHAN_H_
#define _CONTCHAN_H_

#include <stdint.h>
#include <linux/if_ether.h>

#define CCHAN_GATEWAY_CONFIG       0x01
#define CCHAN_CONTROLLER_CONFIG    0x02
#define CCHAN_SHUTDOWN             0x03

struct cchan_request {
    uint8_t     type;
    uint8_t     hw_addr[ETH_ALEN];
    double      latitude;
    double      longitude;
} __attribute__((__packed__));
#define MIN_REQUEST_LEN (sizeof(struct cchan_request))

struct cchan_response {
    uint8_t     type;
    uint32_t    priv_ip;
    uint32_t    lease_time;
    uint16_t    unique_id;
    uint8_t     controllers;
} __attribute__((__packed__));
#define MIN_RESPONSE_LEN (sizeof(struct cchan_response))

struct cchan_controller_info {
    uint32_t    priv_ip;
    uint32_t    pub_ip;
} __attribute__((__packed__));

uint32_t obtain_lease(const char* wiroot_ip, unsigned short wiroot_port);
int get_device_mac(const char* __restrict__ device, uint8_t* __restrict__ dest, int destlen);

#endif //_CONTCHAN_H_

