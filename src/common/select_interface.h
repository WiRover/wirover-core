#ifndef SELECTINTERFACE_H
#define SELECTINTERFACE_H

#include "interface.h"
#include "flow_table.h"

int sendPacket(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife);
int send_sock_packet(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct sockaddr_storage *dst);

//These are defined separately by both the controller and gateway
//Their purpose is to choose source and destination interfaces for
//outgoing packets, this includes handling failover etc. when an
//interface is no longer active
struct interface *select_src_interface(struct flow_entry *fe);
struct interface *select_dst_interface(struct flow_entry *fe);

#endif /* SELECTINTERFACE_H */