#ifndef _ICMP_PING_H_
#define _ICMP_PING_H_
#include "interface.h"
#include "packet.h"

int send_icmp_ping(struct interface *ife);
int handle_incoming_icmp_ping(struct interface *ife, struct packet *pkt);
struct sockaddr_storage * icmp_ping_dest;

#endif