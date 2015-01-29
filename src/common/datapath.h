#ifndef DATAPATH_H
#define DATAPATH_H

#include "tunnel.h"

/* Return value of send_packet indicating that packet should be queued. */
#define SEND_QUEUE -2

struct packet;

int start_data_thread(struct tunnel *tun_in);
int stop_datapath_thread();
int send_packet(struct packet *pkt, int allow_ife_enqueue, int allow_flow_enqueue);
int send_encap_packet_ife(uint8_t flags, char *packet, int size, struct interface *src_ife, struct interface *dst_ife,
    uint32_t *remote_ts, uint32_t global_seq);
int send_encap_packet_dst(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst, struct interface *update_ife, uint32_t global_seq, uint32_t *remote_ts);
int send_encap_packet_dst_noinfo(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst);
int send_nat_packet(char *orig_packet, int orig_size, struct interface *src_ife);
int send_ife_packet(char *packet, int size, struct interface *ife, int sockfd, struct sockaddr *dst);

#endif
