#ifndef SELECTINTERFACE_H
#define SELECTINTERFACE_H

#include "interface.h"

int sendPacket(char *packet, int size, struct interface *ife, struct sockaddr_in *dst, uint32_t *pseq_num);

#endif /* SELECTINTERFACE_H */