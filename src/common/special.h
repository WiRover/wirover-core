/* vim: set et ts=4 sw=4: */

/*
 * S P E C I A L . H
 */

#ifndef _SPECIAL_H_
#define _SPECIAL_H_

#ifdef CONFIG_USE_GPSD
#include <gps.h>
#endif
#include "tunnelInterface.h"

#define SPECIAL_PKT_SEQ_NO 0xffffffff
#define NAT_PUNCH_SEQ_NO 0xffffffff
#define MAX_PACKET 1400

#define PING_SIZE    1500
#define PING_HISTORY 10
#define PING_SPACING 0
#define BURST_FILTER 0

// Packet Types
#define SPKT_NAT_PUNCH      0x01
#define SPKT_PING_BURST     0x02
#define SPKT_UDP_PING       0x03
#define SPKT_PING_STATS     0x04

// Active bandwidth packet types
#define SPKT_ACTBW_CTS      0x10
#define SPKT_ACTBW_BURST    0x11
#define SPKT_ACTBW_STATS    0x12

// For weighted averages
#define ALPHA .9
#define BETA  .1

struct gw_link;

struct nat_punch_pkt {
    uint32_t    seq_no;
    uint16_t    type;
    uint8_t     hw_addr[ETH_ALEN];
    uint32_t    priv_ip;
    uint16_t    algo;
    char        device[IFNAMSIZ];
    uint32_t    pub_ip;
    uint16_t    state;
    uint16_t    src_port;
    int16_t     weight;
    uint16_t    link_id;
    char        network[NETWORK_NAME_LENGTH];
} __attribute__((__packed__));

int sendUDPBurst(char *device, short node_id, short link_id, uint32_t myIP, uint32_t remoteIP, int burst_size);
//int sendUDPPing(char *device, short node_id, short link_id, unsigned long int myIP, unsigned long int remoteIP, int burst_size);
int handleSpecialPacket(int size, char *buf, struct sockaddr_in *from, int sockfd, struct timeval *kernel_rcv_time);
int handleUDPPing(int sockfd, char *packet, struct sockaddr *from, struct timeval *kernel_delay);
void packetPairGw(char *dev_name);
void packetPairCont(struct gw_link *link, char *dev_name);

#ifdef GATEWAY
int natPunch(struct link *ife, uint32_t dAddr, uint16_t dPort, uint16_t sPort);
#endif


#endif
