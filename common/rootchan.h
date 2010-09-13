#ifndef _ROOTCHAN_H_
#define _ROOTCHAN_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include "netlink.h"

// Root server will inform gateway of at most 3 controllers
#define MAX_CONTROLLERS     3

#define RCHAN_GATEWAY_CONFIG       0x01
#define RCHAN_CONTROLLER_CONFIG    0x02
#define RCHAN_SHUTDOWN             0x03

struct controller_info {
    uint32_t    priv_ip;
    uint32_t    pub_ip;
    uint16_t    base_port;
} __attribute__((__packed__));

struct rchan_request {
    uint8_t     type;
    uint8_t     hw_addr[ETH_ALEN];
    double      latitude;
    double      longitude;
    uint16_t    base_port;
} __attribute__((__packed__));
#define MIN_REQUEST_LEN (sizeof(struct rchan_request))

struct rchan_response {
    uint8_t     type;
    uint32_t    priv_ip;
    uint32_t    lease_time;
    uint16_t    unique_id;
    uint8_t     controllers;

    struct controller_info cinfo[MAX_CONTROLLERS];
} __attribute__((__packed__));
#define MIN_RESPONSE_LEN (offsetof(struct rchan_response, cinfo))

struct lease_info {
    uint32_t    priv_ip;
    uint32_t    time_limit;
    uint16_t    unique_id;

    unsigned int    controllers;
    struct controller_info* cinfo;
};

struct lease_info* obtain_lease(const char* wiroot_ip, unsigned short wiroot_port, unsigned short base_port);
int get_device_mac(const char* __restrict__ device, uint8_t* __restrict__ dest, int destlen);

uint32_t get_private_ip();
uint16_t get_unique_id();

const struct lease_info* get_lease_info();

int get_controller_addr(struct sockaddr* addr, socklen_t addr_len);
unsigned short get_controller_base_port();

#endif //_ROOTCHAN_H_

