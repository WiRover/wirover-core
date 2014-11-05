#ifndef TUNNEL_H
#define TUNNEL_H

#include <netinet/in.h>
#include <linux/if.h>
#include <sys/socket.h>
#include "tunnel.h"
#include "interface.h"

#define TUNTAP_OFFSET 4

#define TUNHDR_NO_TIMESTAMP 0xFFFFFFFF
#define TUNNEL_LATENCY_INVALID 0xFFFFFFFF

#define TUNTYPE_DATA        0x01
#define TUNTYPE_PING        0x02
#define TUNTYPE_ACK         0x03
#define TUNTYPE_ACKREQ      0x04
#define TUNTYPE_ERROR       0x05

#define TUNERROR_BAD_NODE   0x01
#define TUNERROR_BAD_LINK   0x02

struct tunhdr {
    __u8        type;
    __u8        version;
    __be16      header_len;

    __be32      global_seq;
    __be32      link_seq;
    uint16_t    link_id;
    uint16_t    node_id;
    __be32      path_ack;

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
int add_tunnel_header(uint8_t type, char *orig_packet, int size, char *dst_packet, 
    struct interface *src_ife, struct interface *update_ife, uint32_t *global_seq);

#endif //TUNNEL_H

