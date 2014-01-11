/*
 *  S E L E C T  I N T E R F A C E . H
 */

#ifndef SELECT_INTERFACE_H
#define SELECT_INTERFACE_H

struct link;
char code_buffer[MTU];

int initSelectInterface(struct tunnel *tun);
struct link *selectInterface(int algo, unsigned short port, int size);
int stripePacket(char *packet, int size, int algo);
int xorPackets(char *buf, int len);
#endif
