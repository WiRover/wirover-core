#ifndef HEADERS_H
#define HEADERS_H

#include <linux/ip.h>
#include "packet.h"

unsigned short compute_checksum(unsigned short *addr, unsigned int count);
void compute_ip_checksum(struct iphdr *ip_hdr);
void compute_transport_checksum(struct packet *pkt);
void compute_tcp_checksum(char *tcp_hdr_body, int length, __be32 src, __be32 dst);
void compute_udp_checksum(char *tcp_hdr_body, int length, __be32 src, __be32 dst);

#endif