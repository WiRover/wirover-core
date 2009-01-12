/*
 * headerParse.h
 */

#ifndef HEADER_PARSE_H
#define HEADER_PARSE_H

#include <stdint.h>
#include <linux/tcp.h>
#include <netinet/ip.h>

struct flow_tuple {
    uint8_t net_proto;
    uint32_t dAddr;
    uint32_t sAddr;
    uint8_t proto;
    uint16_t dPort;
    uint16_t sPort;

};

int fill_flow_tuple(struct iphdr*, struct tcphdr*, struct flow_tuple*);


#endif //HEADER_PARSE_H
