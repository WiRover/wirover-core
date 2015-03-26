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

#define TUNTYPE_TYPE_MASK       0x0F
#define TUNTYPE_DATA            0x01
#define TUNTYPE_PING            0x02
#define TUNTYPE_ACK             0x03
#define TUNTYPE_ACKREQ          0x04
#define TUNTYPE_ERROR           0x05
#define TUNTYPE_RXREPORT        0x06

#define TUNTYPE_CONTROL_MASK    0xF0
#define TUNTYPE_FLOW_INFO       0x10
#define TUNTYPE_DUPLICATE       0x20

#define TUNERROR_BAD_NODE   0x01
#define TUNERROR_BAD_LINK   0x02
#define TUNERROR_BAD_FLOW   0x03

struct tunhdr {
    __u8        type;
    __u8        version;

    __be32      global_seq;
    __be32      link_seq;
    uint16_t    link_id;
    uint16_t    node_id;
    __be32      path_ack;

    __be32      local_ts;
    __be32      remote_ts;
} __attribute__((__packed__));

struct tunnel {
    char name[IFNAMSIZ];
    __be32 n_private_ip;
    __be32 n_netmask;

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
void add_tunnel_header(uint8_t type, struct packet *pkt, struct interface *src_ife,
    struct interface *update_ife, uint32_t global_seq, uint32_t *remote_ts);

#endif //TUNNEL_H

