#ifndef DATAPATH_H
#define DATAPATH_H

#include "tunnel.h"

int handlePackets(struct tunnel *tun);
int start_data_thread(struct tunnel *tun_in);
#ifdef GATEWAY
int set_cont_dst(uint32_t cont_ip, uint16_t cont_port);
#endif
#endif