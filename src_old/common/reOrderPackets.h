/*
 *  R E  O R D E R  P A C K E T S . H
 */

#ifndef REORDERPACKETS_H
#define REORDERPACKETS_H

// Function headers
int reOrderInit();
int createReOrderThread();
int destroyReOrderThread();
void *reOrderThreadFunc(void *arg);
int reOrderPacket(char *data, int dataLen, int rawsock, uint32_t SeqNo, uint16_t codeLen);
int recoverPacket(int pkt_index, int coded_index);
int unxorPackets(int pkt_index, int coded_index, char *buf, int len);
int getCodedPacket(int index);
#endif
