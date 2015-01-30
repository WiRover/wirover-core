#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/if.h>
#include <netinet/in.h>

#include "uthash.h"
#include "packet_buffer.h"
#include "ipaddr.h"
#include "rateinfer.h"

#define NETWORK_NAME_LENGTH 16

enum if_state {
    INIT_INACTIVE = 0,
    ACTIVE,
    INACTIVE,
    DEAD
};

/* Set after the source address and port are verified by a ping.  Checking this
 * is necessary because the source may be behind a NAT. */
#define IFFLAG_SOURCE_VERIFIED 0x00000001

struct interface {
    int                 index; //interface index assigned by kernel
    int                 node_id; //Unique node_id assigned by root server
    char                name[IFNAMSIZ];
    char                network[NETWORK_NAME_LENGTH];
    enum if_state       state;
    int                 priority;

    //This is for local interfaces
    int                 packets_since_ack;
    int                 local_seq;
    int                 remote_ack;
    int                 remote_seq;
    struct timeval      rx_time;
    struct timeval      tx_time;
    struct timeval      st_time;

    int                 flags;

    /* These are in network byte order. */
    struct in_addr      public_ip;
    uint16_t            data_port;
    uint16_t            control_port;

    time_t              ping_interval;
    time_t              ping_timeout;

    struct timeval      last_ping_time;
    struct timeval      last_ping_success;

    uint32_t            next_ping_seq_no;
    uint32_t            last_ping_seq_no;

    double              est_downlink_bw;
    double              est_uplink_bw;

    unsigned long       tx_bytes;
    unsigned long       rx_bytes;

    unsigned int        packets;
    unsigned int        packets_lost;
    unsigned int        out_of_order_packets;
    
    struct retrans_buffer rt_buffer;

    double              avg_rtt;
    double              avg_downlink_bw;
    double              avg_uplink_bw;
    int                 sockfd;
    int                 raw_tcp_sockfd;
    int                 raw_udp_sockfd;
    int                 raw_icmp_sockfd;


    // default gateway for routing if needed
    struct in_addr      gateway_ip;

#ifdef CONTROLLER
    struct timeval last_passive;
    uint64_t prev_bytes_tx;
    uint64_t prev_bytes_rx;
    uint32_t prev_packets_tx;
    uint32_t prev_packets_rx;

    int update_num;
#endif /* CONTROLLER */

    double meas_bw_up;
    double meas_bw_down;
    time_t meas_bw_time;

    /* Information for controlling transmit rate. */
    struct rate_control ingress_rate_control;
    struct rate_control egress_rate_control;

    /* Information for estimating downlink rate */
    float base_rtt_diff;
    struct circular_buffer rtt_buffer;

    /* Track the most recent burst of packets received. */
    struct packet_burst burst;

    struct interface* next;
    struct interface* prev;
};

struct interface_copy {
    int index;
    char name[IFNAMSIZ];
};

// All threads accessing the list need to lock and unlock it the rwlock.
extern struct interface*    interface_list;
extern struct rwlock        interface_list_lock;

struct interface* alloc_interface(int node_id);
int change_interface_state(struct interface *ife, enum if_state state);
int interface_bind(struct interface *ife, int bind_port);
void free_interface(struct interface* ife);

//These are currently implemented by searching the linked list, since the list
//will typically contain around 1-3 elements.  One can very easily change
//these functions to use uthash if it helps.
struct interface *find_interface_by_index(struct interface *head, unsigned int index);
struct interface *find_interface_by_name(struct interface *head, const char *name);
struct interface *find_interface_by_network(struct interface *head, const char *network);
struct interface *find_interface_at_pos(struct interface *head, unsigned pos);
int max_active_interface_priority(struct interface *head);

int count_all_interfaces(const struct interface *head);
int count_active_interfaces(const struct interface *head);

struct interface *find_active_interface(struct interface *head);
int copy_all_interfaces(const struct interface *head, struct interface_copy **out);
int copy_active_interfaces(const struct interface *head, struct interface_copy **out);

double calc_bw_up(const struct interface *ife);
double calc_bw_down(const struct interface *ife);

double ewma_update(double old_val, double new_val, double new_weight);

int dump_interfaces_to_file(const struct interface *head, const char *filename);
void dump_interface(const struct interface *ife, const char *prepend);
void dump_interfaces(const struct interface *head, const char *prepend);

#endif //_INTERFACE_H_

