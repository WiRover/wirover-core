#ifndef DATAPATH_H
#define DATAPATH_H

#include "tunnel.h"


int start_data_thread(struct tunnel *tun_in);
int send_packet(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife);
int send_sock_packet(uint8_t type, char *packet, int size, struct interface *src_ife, struct sockaddr_storage *dst, struct interface *update_ife);

#endif