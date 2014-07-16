#ifndef TUNNEL_H
#define TUNNEL_H

#include <netinet/in.h>
#include <linux/if.h>
#include <sys/socket.h>
#include "tunnel.h"
#include "interface.h"

#define SEC_TO_USEC 1000000

#define TUNTAP_OFFSET 4

#define TUNHDR_NO_TIMESTAMP 0xFFFFFFFF
#define TUNNEL_LATENCY_INVALID 0xFFFFFFFF

#define TUNFLAG_DATA  0x01
#define TUNFLAG_PING  0x10

struct tunhdr {
    __u8    flags;
    __u8    version;
    __u8    header_len;
    __u8    __pad0;

    __be32  seq;
    __be32  path_ack;

    __be32  send_ts;
    __be32  recv_ts;

    uint16_t   link_id;
    uint16_t   node_id;
    uint16_t   __pad1;
} __attribute__((__packed__));

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
int add_tunnel_header(uint8_t flags, char *orig_packet, int size, char *dst_packet, uint16_t node_id, struct interface *src_ife);

#endif //TUNNEL_H

