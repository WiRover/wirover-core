/*
 *  P A C K E T  D E B U G . H
 */

#ifndef PACKET_DEBUG_H
#define PACKET_DEBUG_H

void hex_to_str(char *ip_addr, int addr);
void print_ethhdr(struct ethhdr *eth_hdr, FILE *file);
void print_iphdr(struct iphdr *header, FILE *file);
void print_tcphdr(unsigned char *header, FILE *file);
void print_udphdr(struct udphdr *udp_header, FILE *file);
void print_pkthdr(unsigned char *header, FILE *file);
void print_encappkt(unsigned char *header, FILE *file);

#endif
