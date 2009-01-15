/*
 *  T U N N E L  I N T E R F A C E . H
 */

#ifndef TUNNEL_INTERFACE_H
#define TUNNEL_INTERFACE_H

#include <netinet/in.h>
#include <linux/if.h>
#include <sys/socket.h>
#include "tunnel.h"

#define SEC_TO_USEC 1000000

#define TUNTAP_OFFSET 4

struct tunnel {
    char name[IFNAMSIZ];
    __be32 n_private_ip;

    int  localPort;
    int  remotePort;
    int  controlPort;

    struct sockaddr_in destAddr;

    int tunnelfd;
};

int    tunnelInit();
void   tunnelCleanup();
void   dumpTunHdr(struct tunhdr *tun_hdr);
void   dumpNetworkTunHdr(struct tunhdr *tun_hdr);
int tunnel_create(uint32_t ip, uint32_t netmask, unsigned mtu);
struct tunnel *getTunnel();

#endif
