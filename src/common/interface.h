#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/if.h>
#include <netinet/in.h>
#include "uthash.h"

#define NETWORK_NAME_LENGTH 16

enum if_state {
    INIT_INACTIVE = 0,
    ACTIVE,
    INACTIVE,
    DEAD
};
enum if_stall_state {
    ST_ACTIVE = 1,
    ST_STALL_WAITING = 2,
    ST_STALLED = 3
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
    enum if_stall_state st_state;
    int                 priority;

    //This is for local interfaces
    int                 packets_since_ack;
    int                 next_seq;
    int                 last_ack;
    time_t              rx_time;

    int                 flags;

    /* These are in network byte order. */
    struct in_addr      public_ip;
    uint16_t            data_port;
    uint16_t            control_port;

    time_t              ping_interval;
    time_t              ping_timeout;

    time_t              last_ping_time;
    time_t              last_ping_success;
    int                 pings_outstanding;

    time_t              next_ping_time;
    time_t              next_ping_timeout;

    uint32_t            next_ping_seq_no;
    uint32_t            last_ping_seq_no;

    unsigned int        packets;
    unsigned int        packets_lost;
    unsigned int        out_of_order_packets;

    double              avg_rtt;
    double              avg_downlink_bw;
    double              avg_uplink_bw;
    int                 sockfd;


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

    long meas_bw;
    long pred_bw;
    time_t meas_bw_time;

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
int interface_bind(struct interface *ife, int bind_port);
void free_interface(struct interface* ife);

//These are currently implemented by searching the linked list, since the list
//will typically contain around 1-3 elements.  One can very easily change
//these functions to use uthash if it helps.
struct interface *find_interface_by_index(struct interface *head, unsigned int index);
struct interface *find_interface_by_name(struct interface *head, const char *name);
struct interface *find_interface_by_network(struct interface *head, const char *network);
struct interface *find_interface_at_pos(struct interface *head, unsigned pos);

int count_all_interfaces(const struct interface *head);
int count_active_interfaces(const struct interface *head);

struct interface *find_active_interface(struct interface *head);
int copy_all_interfaces(const struct interface *head, struct interface_copy **out);
int copy_active_interfaces(const struct interface *head, struct interface_copy **out);

long calc_bw_hint(struct interface *ife);

double ewma_update(double old_val, double new_val, double new_weight);

void dump_interfaces(const struct interface *head, const char *prepend);

#endif //_INTERFACE_H_

