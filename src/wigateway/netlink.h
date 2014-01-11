/*
 * N E T  L I N K . H
 */

#ifndef NETLINK_H 
#define NETLINK_H

// Netlink thread
int createNetLinkThread();
int destroyNetLinkThread();
void *netLinkThreadFunc();

int handleNetLinkPacket();
int getNetLinkSocket();
int createNetLinkSocket();

#endif
