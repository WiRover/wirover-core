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
#include <openssl/sha.h>

#include "interface.h"
#include "ipaddr.h"
#include "config.h"

#define MAX_INTERFACES    6

#define CCHAN_NOTIFICATION      0x10
#define CCHAN_STARTUP           0x11
#define CCHAN_INTERFACE         0x12
#define CCHAN_SHUTDOWN          0x13

#define SHUTDOWN_REASON_NORMAL  0x01
#define SHUTDOWN_REASON_CRASH   0x02

#define CCHAN_CONNECT_TIMEOUT_SEC  5
#define CCHAN_RESPONSE_TIMEOUT_SEC 5

/* A typical control channel message contains a notification block followed by
 * one or more interface information blocks. The protocol uses
 * length fields to indicate the length of the current block and hence the
 * start of the next block. Therefore, if you want to add new fields, you can
 * add them at the structure without breaking backwards compatibility. If the
 * receiver does not recognize the new fields, it can still use the length
 * field to skip to the next block. Removing fields always breaks backwards
 * compatibility, however. 
 *
 */

/* Minimal header used during notification parsing. */
struct cchan_header {
    uint8_t     type;
    uint8_t     len;
} __attribute__((__packed__));

struct cchan_notification {
    uint8_t     type;
    uint16_t     len;

    uint8_t     ver_maj;
    uint8_t     ver_min;
    uint16_t    ver_rev;

    ipaddr_t    priv_ip;
    uint16_t    unique_id;
    uint8_t     key[SHA256_DIGEST_LENGTH];
    uint16_t    bw_port;
    char        hash[NODE_HASH_SIZE];

    /* Interface list follows */
} __attribute__((__packed__));
#define MIN_NOTIFICATION_LEN (sizeof(struct cchan_notification))

struct interface_info {
    uint8_t     type;
    uint16_t     len;
    
    uint32_t    link_id;
    char        ifname[IFNAMSIZ];
    char        network[NETWORK_NAME_LENGTH];
    uint8_t     state;
    int8_t      priority;

    uint32_t    local_ip;
    uint16_t    data_port;
} __attribute__((__packed__));
#define MIN_INTERFACE_INFO_LEN (sizeof(struct interface_info))

struct cchan_shutdown {
    uint8_t     type;
    uint16_t     len;

    ipaddr_t    priv_ip;
    uint16_t    unique_id;
    uint8_t     key[SHA256_DIGEST_LENGTH];

    uint8_t     reason;
} __attribute__((__packed__));

#ifdef CONTROLLER
int process_notification(int sockfd, const char* packet, unsigned int pkt_len, uint16_t bw_port);
#endif

#ifdef GATEWAY
int send_notification(int max_tries);
uint16_t get_remote_bw_port();
int send_startup_notification();
int send_shutdown_notification();

extern uint8_t private_key[SHA256_DIGEST_LENGTH];
extern uint16_t remote_unique_id;
#endif

#endif //_CONTCHAN_H_

