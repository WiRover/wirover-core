#ifndef SELECTINTERFACE_H
#define SELECTINTERFACE_H

#include "interface.h"

int sendPacket(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife);

#endif /* SELECTINTERFACE_H */