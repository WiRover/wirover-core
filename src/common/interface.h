/*
 * I N T E R F A C E . H
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <pthread.h>
#include "../common/parameters.h"
#include "../common/tunnelInterface.h"
//#include "../common/udp_ping.h"

#include <sys/time.h>

struct link;
struct interface;

// Function prototypes for accessing local globals
struct link    *addInterface(char *name);

int                 discoverWeights();
int                 interfaceBind(struct link *ife, int bind_port);
int                 setIfIpFromIfreq(struct link *ife, struct ifreq *addr);
void                setDevDownWeight(struct link *ife, float weight);
void                setDevUpWeight(struct link *ife, float weight);
void                dumpInterfaces();
void                interfaceDump(struct link *ife);
void                demoInterfaceDump(struct link *head);


// Cisco API
float               getDownlinkBandwidth(struct interface *ife);
float               getUplinkBandwidth(struct interface *ife);
float               getLossRate(struct interface *ife);
int                 getLatency(struct interface *ife);

// Number of adjacent pings to send out when sendUDPBurst is called
// Can only be a maximum of 5 as 3G interfaces will drop anything above that
#define NUM_PINGS 5

struct statistics {
    short type;             /* IF type               */
    short flags;            /* Various flags         */
    int metric;             /* Routing metric        */
    int mtu;                /* MTU value             */
    int rtt;                /* Round Trip Time       */
    int t_ul;                /* Uplink Latency (includes clock offset) */
    int tx_queue_len;       /* Transmit queue length */
    struct timeval last_good_rtt;      /* Unix timestamp of last good rtt */
    int num_burst_lost;

	unsigned long long bytes_sent;   /* bytes sent out on this interface */
	unsigned long long bytes_recvd;  /* bytes received on this interface */

    // Algorithm Info
    short dn_weight;
    short up_weight;

    // Loss/Latency
    float loss_rate;
    int   latency;

    // Dynamic Bandwidth Info
    short transfer_in_progress;

    float static_downlink_bw;
    float downlink_bw;
    float downlink_bw_avg;
    float downlink_avg_count;
    float downlink_bw_weighted;
    float downlink_total_bw;

    float static_uplink_bw;
    float uplink_bw;
    float uplink_bw_avg;
    float uplink_avg_count;
    float uplink_bw_weighted;
    float uplink_total_bw;

    long  last_bw_test;

    // Weight
    int curr_weight;
    int udp_ping_losses;

    // Netlink stats
    short rtm_newlink_count;
    short rtm_newaddr_count;
};

//struct interface {
//    struct interface *next, *prev;
//
//    short link_id;
//
//    // Hardware info
//    char name[IFNAMSIZ];        /* interface name        */
//    char dev_name[IFNAMSIZ];
//    char hwaddr[32];            /* HW address            */
//    struct sockaddr addr;       /* IP address            */
//    struct sockaddr ethaddr;    /* MAC address           */
//    struct statistics stats;    /* Statistics            */
//    int statistics_valid;       /* Valid bit             */
//
//    // Transfer socket
//    int trans_sockfd;
//
//    // IP infromation
//    char p_ip[20];
//    uint32_t n_ip;
//
//    // Socket info
//    int has_ip;
//    int is_valid;
//    int sockfd;
//
//    // Buffering info
//    pthread_mutex_t lock_mutex;
//    pthread_mutex_t condition_mutex;
//    pthread_cond_t  condition_cond;
//    struct buffer_node *buf_head, *buf_tail, *buf_temp;
//    int buffer_size;
//    int total_bytes;
//    int total_sent;
//    int max_buf_size;
//
//    // Burst buffer for UDP Pings
//    struct ping_pkt *burst_buf[NUM_PINGS];
//    
//    // Match the pid of the pppd to the interface
//    int ppp_pid;
//
//    // Keep the state of the interface
//    enum IF_STATE state;
//
//    // Information for GW if interface has one
//    int has_gw;
//    char gw_ip[20];
//
////	unsigned short  local_seq_no_out;
////	unsigned short  local_seq_no_in;
////	unsigned int    packets_lost;
////	unsigned int    out_of_order_packets;
//};

#ifdef GATEWAY
struct interface *getInterface(int link_id);
#endif

int                 interfaceCleanup(struct link *head);
int                 fix_routes();
void                interfacePrint(struct link *head);
void                interfaceQuickPrint(struct link *head);

#endif
