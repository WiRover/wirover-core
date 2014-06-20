/*
 * C O N T  C H A N . H
 */


#ifndef CONTCHAN_H
#define CONTCHAN_H

#include "interface.h"
#include "packetBuffer.h"

// Packet Types
#define CONTCHAN_REQUEST        1
#define CONTCHAN_RESPONSE       2
#define CONTCHAN_NOTIFICATION   3
#define CONTCHAN_NATPUNCH       4
#define CONTCHAN_SHUTDOWN       5

// In hours
#define LEASE_TIME 12 * 60 * 60
#define LEASE_TIMEO 30 * 60 
#define BUFF_MAX        255
#define RADIX           10
#define MAX_IP_ASCII    20

typedef enum {
    GW_STATE_UNKNOWN,
    GW_STATE_ACTIVE,   //actively transmitting
    GW_STATE_INACTIVE, //aka MIA
    GW_STATE_OFFLINE   //notified us that it was going down
} gw_state_t;

struct contchan_request {
    uint16_t        type;
    unsigned char   unique_id[ETH_ALEN];
    uint16_t        algo;
    uint8_t         num_links;
} __attribute__((__packed__));

struct contchan_link {
    char        ifname[IFNAMSIZ];
    char        pub_ip[IP_NETWORK_SIZE];
    char        network[NETWORK_NAME_LENGTH];
    uint16_t    state;
    uint16_t    weight;
    uint16_t    link_id;
} __attribute__((__packed__));

struct contchan_response {
    uint16_t    type;
    uint32_t    priv_ip;
    uint32_t    lease_time;
    uint32_t    node_id;
} __attribute__((__packed__));

// General function declarations
int     configureControlChannel();
int     handleControlPackets(int wigateway_sock);
void    setForwardPorts(short start, short end);

// Control channel thread
void    *contChanThreadFunc(void *arg);
int     createContChanThread();
int     destroyContChanThread();

// Functions to manipulate gateway structures
struct wigateway *getHeadGW();
int     removeWigateway(unsigned char *id);
void    removeStaleWigateways();
int     cleanupWigateways();

// Search Gateway Functions
struct  wigateway *searchWigatewaysByNodeID(int node_id);
struct  wigateway *searchWigatewaysByID(unsigned char *id);
struct  wigateway *searchWigatewaysByIP(uint32_t gw_private_addr);
struct  wigateway *searchWigatewaysByPubIP(uint32_t public_ip);
struct  wigateway *searchWigatewaysByPort(short port);

// Linked list of 'wigateways'
struct wigateway
{
    unsigned char id[ETH_ALEN];
    unsigned int node_id;

    gw_state_t      state;
    time_t          last_state_change;

    // The WiGateway's private IP (IP of TUN device)
    char       p_private_ip[MAX_IP_ASCII];
    uint32_t   n_private_ip;

    short   algo;
    short   fwd_port;

    int num_interfaces;
    int num_ip_entries;
    int if_total_weight;
    int curr_interface;
    int curr_RndRobin;

    // Byte statisitics for this gatewa
    unsigned long long num_bytes_recvd_from;
    unsigned long long num_bytes_sent_to;

    time_t last_seen_pkt_time;

    // Latest GPS data
    int gps_status;
    double latitude;
    double longitude;
    double altitude;

    time_t      lastGpsTime;
    unsigned    lastGpsRowId;

    unsigned seq_num;
    struct buffer_storage *packet_buffer[PACKET_BUFFER_SIZE];

    // A linked list of the WiGateway's private IP's
	struct link*	head_link;

    // These will be unix time stamps (seconds since epoch)
    uint32_t    lease_begin;
    uint32_t    lease_end;

    struct wigateway *next;
    struct wigateway *prev;
};

#ifdef GATEWAY

short getNodeID();
void setNodeID(int id);
unsigned char *getUniqueID();
void setUniqueID(unsigned char *mac_addr);
int createSocket();

// Control Channel functions
int getLease();
int notifyController();
int shutdownContChan();

#endif

#ifdef CONTROLLER
struct wigateway* createGateway();
int leaseAvailable(uint32_t ip, unsigned short port);
int grantLease(struct wigateway *gw, int sockfd);
int renewLease(struct wigateway *gw, int sockfd);
int restoreLease(struct wigateway *gw, uint32_t ip, unsigned short port);
int computeNodeId(unsigned char* hw_addr, unsigned int len);
int addGwLink(struct wigateway *gw, const char* __restrict__ if_name,
              const char* __restrict__ p_ip, unsigned short data_port,
              const char* __restrict__ network,
              short state, short weight, short link_id, int in_list_flag);
void changeGwState(struct wigateway* gw, gw_state_t state);
#endif //CONTROLLER

void dumpWigateways();

// Structure definitions common to both
struct wicontroller
{
    char *  p_controller_ip;
    uint32_t    n_controller_ip;
    short   h_controller_port;
    short   n_controller_port;

    short   start_fwd_port;
    short   end_fwd_port;

    struct  sockaddr_in addr;
};

#endif

// vim: set et ts=4 sw=4 cindent:

