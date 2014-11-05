#ifndef DATAPATH_H
#define DATAPATH_H

#include "tunnel.h"


int start_data_thread(struct tunnel *tun_in);
int send_packet(char *packet, int size);
int send_encap_packet_ife(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife, uint32_t *remote_ts);
int send_encap_packet_dst(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst, struct interface *update_ife, uint32_t *global_seq, uint32_t *remote_ts);
int send_encap_packet_dst_noinfo(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst);
int send_nat_packet(char *orig_packet, int orig_size, struct interface *src_ife);

#endif