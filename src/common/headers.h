#ifndef HEADERS_H
#define HEADERS_H

#include <stdint.h>
#include "packet.h"

struct iphdr;

unsigned short compute_checksum(unsigned short *addr, unsigned int count);
void compute_ip_checksum(struct iphdr *ip_hdr);
void compute_transport_checksum(struct packet *pkt);
void compute_tcp_checksum(char *tcp_hdr_body, int length, uint32_t src, uint32_t dst);
void compute_udp_checksum(char *tcp_hdr_body, int length, uint32_t src, uint32_t dst);

#endif
