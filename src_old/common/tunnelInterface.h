/*
 *  T U N N E L  I N T E R F A C E . H
 */

#ifndef TUNNEL_INTERFACE_H
#define TUNNEL_INTERFACE_H

#include <netinet/in.h>
#include <linux/if.h>
#include <sys/socket.h>

#define SEC_TO_USEC 1000000

struct link;

struct tunhdr {
    uint32_t seq_no;

    uint16_t prev_len;
    uint32_t send_ts;
    uint32_t recv_ts;
    uint32_t service;

    uint16_t client_id;
    uint16_t node_id;
    uint16_t link_id;
    uint16_t local_seq_no;
} __attribute__((__packed__));

#define TUNHDR_NO_TIMESTAMP 0xFFFFFFFF
#define TUNNEL_LATENCY_INVALID 0xFFFFFFFF

/*
 * Latency estimation protocol:
 *
 * The sender always puts his current time in send_ts as microseconds modulo
 * 2^32.  If the sender received a packet recently on the same link, he can
 * also fill in recv_ts and service, where "recently" means at least less
 * than 2^32 microseconds but should be much less for a good estimation.  The
 * value for recv_ts is copied from the send_ts of the last packet he received.
 * The value for service is the number of microseconds that passed between
 * the receipt of the packet and the time of the outgoing packet.  If the
 * sender is not able to fill in recv_ts and service, he should use the
 * special value TUNHDR_NO_TIMESTAMP.  Note that on very rare occasions, the
 * true value of recv_ts may be equal to TUNHDR_NO_TIMESTAMP, but the
 * service may not be equal to TUNHDR_NO_TIMESTAMP (0xFFFFFFFF) because
 * that would be unacceptably large.
 *
 * This method for latency estimation is bidirectional and does not require
 * synchronized clocks.
 */

struct tunnel {
    char name[IFNAMSIZ];
    char localIP[IFNAMSIZ];
    char remoteIP[IFNAMSIZ];

    uint32_t n_private_ip;

    int  localPort;
    int  remotePort;
    int  controlPort;

    struct sockaddr_in destAddr;

    int tunnelfd;
};

uint32_t   getTunPrivIP();
int    getTunnelDescriptor();
int    setTunnelDescriptor(int value);
int    setTunPrivIP(int ip);
int    setTunLocalIP(char *ip);
char   *getTunLocalIP();
char   *getTunRemoteIP();
int    getTunLocalPort();
int    tunnelInit();
void   tunnelCleanup();
void   dumpTunHdr(struct tunhdr *tun_hdr);
void   dumpNetworkTunHdr(struct tunhdr *tun_hdr);
struct tunnel *tunnelCreate();
struct tunnel *getTunnel();

struct tunnel_measurement {
    float    latency;
    float    bandwidth;
};

uint32_t getTunnelTimestamp(const struct timeval *tv);
void     fillTunnelTimestamps(struct tunhdr *tun_hdr, struct link *link);
unsigned __attribute__((__deprecated__))
        computeTunnelLatency(const struct tunhdr *tun_hdr,
        const struct timeval *arrival_time);
int     finishTunnelMeasurement(struct tunnel_measurement *result,
        struct link *link, const struct tunhdr *tun_hdr, unsigned pkt_len, 
        const struct timeval *arrival_time);
void    updateTunnelTimestamps(struct link *link, const struct tunhdr *tun_hdr,
        unsigned pkt_len, const struct timeval *arrival_time);

#endif
