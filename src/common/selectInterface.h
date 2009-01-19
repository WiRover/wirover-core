#ifndef SELECTINTERFACE_H
#define SELECTINTERFACE_H

#include "interface.h"

int sendPacket(char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife, uint32_t *pseq_num);

#endif /* SELECTINTERFACE_H */