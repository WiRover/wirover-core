#ifndef _ROOTCHAN_H_
#define _ROOTCHAN_H_

#include <stdint.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include "netlink.h"

#define RCHAN_GATEWAY_CONFIG       0x01
#define RCHAN_CONTROLLER_CONFIG    0x02
#define RCHAN_SHUTDOWN             0x03

struct rchan_request {
    uint8_t     type;
    uint8_t     hw_addr[ETH_ALEN];
    double      latitude;
    double      longitude;
} __attribute__((__packed__));
#define MIN_REQUEST_LEN (sizeof(struct rchan_request))

struct rchan_response {
    uint8_t     type;
    uint32_t    priv_ip;
    uint32_t    lease_time;
    uint16_t    unique_id;
    uint8_t     controllers;
} __attribute__((__packed__));
#define MIN_RESPONSE_LEN (sizeof(struct rchan_response))

struct rchan_controller_info {
    uint32_t    priv_ip;
    uint32_t    pub_ip;
} __attribute__((__packed__));

struct lease_info {
    uint32_t    priv_ip;
    uint32_t    time_limit;
    uint16_t    unique_id;

    unsigned int    controllers;
    struct rchan_controller_info* cinfo;
};

struct lease_info* obtain_lease(const char* wiroot_ip, unsigned short wiroot_port);
int get_device_mac(const char* __restrict__ device, uint8_t* __restrict__ dest, int destlen);

uint32_t get_private_ip();
uint16_t get_unique_id();

#endif //_ROOTCHAN_H_

