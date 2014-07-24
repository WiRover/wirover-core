#ifndef _ROOTCHAN_H_
#define _ROOTCHAN_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include "ipaddr.h"
#include "netlink.h"
#include "interface.h"

// Root server will inform gateway of at most 3 controllers
#define MAX_CONTROLLERS     3

#define RCHAN_CONNECT_TIMEOUT_SEC  5

struct controller_info {
    ipaddr_t          priv_ip;
    ipaddr_t          pub_ip;
    uint16_t          data_port;
    uint16_t          control_port;
    uint16_t          unique_id;
} __attribute__((__packed__));

struct rchan_response {
    uint8_t     type;
    ipaddr_t    priv_ip;
    uint8_t     priv_subnet_size;
    uint32_t    lease_time;
    uint16_t    unique_id;
    uint8_t     controllers;

    struct controller_info cinfo[MAX_CONTROLLERS];
} __attribute__((__packed__));
#define MIN_RESPONSE_LEN (offsetof(struct rchan_response, cinfo))

/* Types for rchanhdr */
#define RCHAN_REGISTER_CONTROLLER   0x01
#define RCHAN_REGISTER_GATEWAY      0x02
#define RCHAN_REGISTRATION_DENIED   0x03
#define RCHAN_ACCESS_REQUEST        0x04

#define RCHAN_RESULT_SUCCESS    0
#define RCHAN_RESULT_DENIED     1

/* Option types */
#define RCHAN_OPTION_END            0x00
#define RCHAN_OPTION_ADDR           0x01
#define RCHAN_OPTION_GSP            0x02
    
struct rchanhdr {
    uint8_t type;
    uint8_t flags;
    uint8_t id_len;
    /* node_id follows */
} __attribute__((__packed__));

/* If the address family is sent as 0, root server will use the connection
 * source address. */
#define RCHAN_USE_SOURCE            0x0000

struct rchan_ctrlreg {
    uint16_t    family;

    union {
        uint32_t ip4;
        uint8_t  ip6[16];
    } addr;

    uint16_t    data_port;
    uint16_t    control_port;

    double      latitude;
    double      longitude;
} __attribute__((__packed__));

struct rchan_gwreg {
    double latitude;
    double longitude;
} __attribute__((__packed__));

struct lease_info {
    ipaddr_t    priv_ip;
    uint8_t     priv_subnet_size;
    uint32_t    time_limit;
    uint16_t    unique_id;

    unsigned int    controllers;
    struct controller_info cinfo[MAX_CONTROLLERS];
};

int register_controller(struct lease_info *lease, const char *wiroot_ip,
        unsigned short wiroot_port, unsigned short data_port, unsigned short control_port);
int register_gateway(struct lease_info *lease, const char *wiroot_ip,
        unsigned short wiroot_port);

int get_node_id_hex(char *dst, int dst_len);
int get_node_id_bin(char *dst, int dst_len);

int get_device_mac(const char* __restrict__ device, uint8_t* __restrict__ dest, int destlen);

uint16_t get_unique_id();

void    get_private_ip(ipaddr_t* dest);
const struct lease_info* get_lease_info();

int get_controller_privip(char *dest, int dest_len);
struct interface *get_controller_ife();

#endif //_ROOTCHAN_H_
