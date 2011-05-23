/*
 * contchan.h
 *
 * The control channel is a TCP connection between a gateway and a controller
 * that the gateway uses to setup and update link states with the controller.
 * This typically consists of notification messages whenever a link's state
 * changes.
 */

#ifndef _CONTCHAN_H_
#define _CONTCHAN_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include "interface.h"
#include "ipaddr.h"

#define MAX_INTERFACES    6

#define CCHAN_NOTIFICATION         0x10

struct interface_info {
    char        ifname[IFNAMSIZ];
    char        network[NETWORK_NAME_LENGTH];
    uint8_t     state;

    uint32_t    local_ip;
    uint16_t    data_port;
} __attribute__((__packed__));

struct cchan_notification {
    uint8_t     type;
    ipaddr_t    priv_ip;
    uint16_t    unique_id;
    int32_t     secret_word;
    uint8_t     interfaces;
    struct interface_info if_info[MAX_INTERFACES];
} __attribute__((__packed__));
#define MIN_NOTIFICATION_LEN (offsetof(struct cchan_notification, if_info))

#ifdef CONTROLLER
int process_notification(const char* packet, unsigned int pkt_len);
#endif

#ifdef GATEWAY
int send_notification();
int32_t get_secret_word();
#endif

#endif //_CONTCHAN_H_

