/*
 * M E A S U R E M E N T S . H
 */

#ifndef PCAPSNIFF_H 
#define PCAPSNIFF_H 

int     calculateWeights();
int     createPcapSniffThread();
int     destroyPcapSniffThread();
void    incrementBytesSent(int link_id, int num_bytes);
void    incrementBytesRecvd(int link_id, int num_bytes);

#endif
