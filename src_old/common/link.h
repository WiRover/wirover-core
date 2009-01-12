/*
 * link.h
 */

#ifndef LINK_H
#define LINK_H

#ifndef IF_STATE_FLAG
#define IF_STATE_FLAG
// State info for interfaces
enum IF_STATE {
    ACTIVE=1,
    INACTIVE,
    DEAD,
    STANDBY
};
#endif

#include "linux/if_ether.h"
#include "../common/interface.h"
#include "../common/passive_bw.h"
struct ping_stats;

/*
 * struct link
 *
 * This structure is used to hold information about the links a gateway uses to
 * communicate with the controller.  The structure is intended to be used by
 * both the controller and the gateway, since they need much of the same
 * information.
 */
struct link {
    short               id;
    char                ifname[IFNAMSIZ];
    int                 ifindex; // Device index as used by netlink messages
    char                hwaddr[ETH_ALEN]; //MAC address stored in binary format
    char                network[NETWORK_NAME_LENGTH];
    enum IF_STATE       state;
    int                 priority;
    time_t              last_packet_received; //Used for detecting failure

    // Local sequence numbers used for packet loss
    int                 seq_no_valid;
    unsigned short      local_seq_no_in;
    unsigned short      local_seq_no_out;

    // Link weights from the wigateway's point of view
    short               curr_weight;
    short               up_weight;
    short               dn_weight;

    // Public IP address - stored as IPv6
    char                p_ip[INET6_ADDRSTRLEN];
    char                n_ip[IP_NETWORK_SIZE];
    unsigned short      data_port; //network byte order

    // Averaged statistics, suitable for decision-making
    double              avg_active_bw_down;
    double              avg_active_bw_up;
    double              avg_rtt;
    double              avg_t_ul;
    // Queueing Delay
    double              que_delay;
    struct timeval      last_sent;

    // Bytes sent and received by the gateway
    unsigned long long  bytes_sent;
    unsigned long long  bytes_recvd;
    unsigned long long  month_sent;
    unsigned long long  month_recvd;
    unsigned long long  quota;
    
    // Used by passive measurement module
    struct passive_stats    pstats_running;
    struct passive_stats    pstats_recent;

    //TODO: We should be more careful about packets sent vs. received.
    unsigned int        packets;
    unsigned int        packets_lost;
    unsigned int        out_of_order_packets;

    //TODO: figure out what to do with these
#ifdef GATEWAY
    // For gateway-specific stats
    struct statistics   stats;
    int                 sockfd;
    
    int                 has_gw;
    char                gw_ip[INET6_ADDRSTRLEN];

    // datagram socket for sending and receiving pings
    int                 ping_socket;
#endif

    // When a tunnel packet is received on this link, save the send_ts field
    // and record the local time of the packet.  We will send the value later
    // so that the other side can compute the latency.
    unsigned            last_tunhdr_send_ts;
    unsigned short      last_pkt_len;
    struct timeval      last_arrival;

    int                 prev_rtt;
    int                 prev_exchange_len;

    // For the linked list, do not modify
    struct link*        next;
    struct link*        prev;
};

// The fields of link_iterator may be read by the user of iterator but must not
// be modified.  If link is null, then the end of the list has been reached.
struct link_iterator {
#ifdef CONTROLLER
    struct wigateway* gw;
#endif
    struct link*      link;
};

struct link* makeLink();
struct link* addLink(struct link* head, struct link* link);

unsigned int countLinks(struct link* head);
unsigned int countActiveLinks(struct link* head);
unsigned int countValidLinks(struct link* head);

struct link* findActiveLink(struct link* head);
struct link* searchLinksById(struct link* head, short id);
struct link* searchLinksByIp(struct link* head, char* ip);
struct link* searchLinksByName(struct link* head, char* ifname);
struct link* searchLinksByIndex(struct link* head, int index);

enum IF_STATE setLinkState(struct link* link, enum IF_STATE state);

// This iterator offers a general way for both the gateway and controller to
// walk through all interfaces.  For the controller, there is the option of
// iterating all interfaces or only those interfaces belonging to a single
// gateway.
void initInterfaceIterator(struct link_iterator* iter, struct link* head);
struct link* nextInterface(struct link_iterator* iter);

void dumpInterfaces(struct link* head, const char* prepend);

// These will return the best estimate of bandwidth when called, may be from
// active or passive measurement.
double getLinkBandwidthDown(struct link* link);
double getLinkBandwidthUp(struct link* link);

unsigned long long incLinkBytesSent(struct link* link, unsigned long long bytes);
unsigned long long incLinkBytesRecvd(struct link* link, unsigned long long bytes);

void updateLinkBandwidth(struct link* link, double bw_down, double bw_up);
void updateLinkRtt(struct link* link, struct ping_stats* stats);

void computeLinkWeights(struct link* head);

int setLinkIp(struct link *link, const struct sockaddr *addr, socklen_t addrlen);
int setLinkIp_p(struct link* link, const char* __restrict__ p_ip);
int setLinkIp_n(struct link* link, const char* __restrict__ n_ip);
uint32_t getLinkIpv4(struct link* link);

int readNetworkName(char* ifname, char* network, unsigned int network_len);

#ifdef GATEWAY
extern struct link* head_link__;
#endif

#endif //LINK_H

// vim: set et ts=4 sw=4 cindent:

