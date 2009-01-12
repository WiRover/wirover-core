/*
 * S E L E C T  I N T E R F A C E . H
 */

#ifndef SELECT_INTERFACE_H
#define SELECT_INTERFACE_H

int initSelectInterface(int port);
int sendAllInterfaces(int fd, char *packet, int size, int offset);
int stripePacket(int fd, char *packet, int size, int offset, int algo);

#endif
