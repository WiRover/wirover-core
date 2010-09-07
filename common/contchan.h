#ifndef _CONTCHAN_H_
#define _CONTCHAN_H_

#include <stdint.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include "netlink.h"

#define CCHAN_NOTIFICATION         0x10

struct cchan_notification {
    uint8_t     type;
    uint32_t    priv_ip;
    uint16_t    unique_id;
    uint8_t     interfaces;
} __attribute__((__packed__));
#define MIN_NOTIFICATION_LEN (sizeof(struct cchan_notification))

struct cchan_interface_info {
    char        ifname[IFNAMSIZ];
    char        network[NETWORK_NAME_LENGTH];
    uint8_t     state;
} __attribute__((__packed__));

#endif //_CONTCHAN_H_

