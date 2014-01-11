/*
 *
 * C O N T  C H A N . C
 *
 * This file contains code for the controller's control channel.
 *
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <limits.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/contChan.h"
#include "../common/packet_debug.h"
#include "../common/special.h"
#include "../common/time_utils.h"
#include "../common/udp_ping.h"
#include "../common/utils.h"
#include "gatewayUpdater.h"

int     createSocket(int n_ip, short port);
int     insertGateway(struct wigateway *gw);
void    handleShutdownMessage(struct contchan_request* request);
uint32_t    findFreeIp();
int     findFreeFwdPort();
void    dumpWicontroller();
void    smallDumpWiGateways();
void    processLease(int sockfd, char * packet, int sizeofpacket, int wigateway_sock);
void    updateWigateway(char *packet, int sizeofpacket);

static pthread_t        cont_chan_thread;
static pthread_mutex_t  scan_gw_mutex = PTHREAD_MUTEX_INITIALIZER;

struct wigateway *head_gw, *tail_gw;
//static struct wicontroller proxy, *pproxy;
static struct sockaddr_storage  proxy_addr;
static socklen_t                proxy_addr_len = 0;
static ipsec_req_t ipsr;

static unsigned short start_fwd_port = 0;
static unsigned short end_fwd_port   = 0;

static struct sockaddr_in dhcp_start_addr;
static int dhcp_range = -1;

/* G E T  H E A D  G W 
 * 
 * Return a pointer to the head in the gateway list
 *
 * Returns (struct wigateway *)
 */
struct wigateway *getHeadGW() 
{
    return head_gw;
} // End function struct wigateway *getHeadGW()

/*
 * C O N F I G U R E   C O N T R O L   C H A N N E L
 *
 * Reads relevant settings from the config file.
 * The necessary order of initialization is (unfortunately)
 * createControlChannel() ... open config file ... configureControlChannel().
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int configureControlChannel()
{
    char* data;
    char* baseAddr;
    char* addrRange;

    if( (data = getDhcpRange()) == NULL ) 
    {  
        DEBUG_MSG("DHCP Range parameter not found in /etc/wirover");
        return FAILURE;
    }
    else
    {
        if ( (baseAddr = strtok(data, CONFIG_FILE_PARAM_DHCP_RANGE_DELIM)) != NULL)
        {
            dhcp_start_addr.sin_addr.s_addr = inet_addr(baseAddr);
        }

        if ( (addrRange = strtok(NULL, CONFIG_FILE_PARAM_DHCP_RANGE_DELIM)) != NULL)
        { 
            dhcp_range = atoi(addrRange);
        }
    }

    return SUCCESS;
}

/*
 * Open the control channel socket.  Returns -1 on failure or the socket fd on
 * success.
 */
static int createContChanSocket()
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family     = AF_INET6;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_protocol   = 0;
    hints.ai_flags      = AI_PASSIVE | AI_NUMERICSERV;

    struct addrinfo *addrinfo = 0;
    int res = getaddrinfo(0, CONTROL_PORT_STR, &hints, &addrinfo);
    if(res != 0) {
        DEBUG_MSG("getaddrinfo failed: %s", gai_strerror(res));
        goto fail;
    }

    int sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
            addrinfo->ai_protocol);
    if(sockfd < 0) {
        ERROR_MSG("create socket failed");
        goto fail_free_addrinfo;
    }

    if(setIPSec(ipsr, sockfd) < 0) {
        DEBUG_MSG("setIPSec failed");
        goto fail_close_socket;
    }
    
    int on = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        ERROR_MSG("setsockopt(SO_REUSEADDR) failed");
        goto fail_close_socket;
    }

    if(bind(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0) {
        ERROR_MSG("bind failed");
        goto fail_close_socket;
    }

    if(listen(sockfd, SOMAXCONN) < 0) {
        ERROR_MSG("listen() failed");
        goto fail_close_socket;
    }

    assert(addrinfo->ai_addrlen <= sizeof(proxy_addr));
    memcpy(&proxy_addr, &addrinfo->ai_addr, addrinfo->ai_addrlen);
    proxy_addr_len = addrinfo->ai_addrlen;

    // Success
    freeaddrinfo(addrinfo);
    return sockfd;

fail_close_socket:
    close(sockfd);
fail_free_addrinfo:
    freeaddrinfo(addrinfo);
fail:
    return -1;
}

/*
 * C R E A T E   G A T E W A Y
 *
 * Returns a dynamically allocated gateway structure
 * with fields initialized to zero.
 */
struct wigateway* createGateway()
{
	struct wigateway* gateway = (struct wigateway*)malloc(sizeof(struct wigateway)); 
    memset(gateway, 0, sizeof(struct wigateway));

    time(&gateway->last_seen_pkt_time);

    gateway->state = GW_STATE_UNKNOWN;

    return gateway;
} // End function createGateway()

/*
 * A D D   G W   L I N K 
 *
 * Function to add an IP address entry to a wigateway structure.
 *
 * Returns (int)
 *     Success: 0
 *     Failure: -1
 *
 */
int addGwLink(struct wigateway *gw, const char* __restrict__ if_name,
              const char* __restrict__ p_ip, unsigned short data_port,
              const char* __restrict__ network, 
              short state, short weight, short link_id, int in_list_flag)
{
    struct link* link = makeLink();

    link->id = link_id;
    strncpy(link->ifname, if_name, sizeof(link->ifname));
    link->state = state;

    // Important, only increment num_interfaces of state == ACTIVE
    if(state == ACTIVE) {
        gw->num_interfaces++;
        gw->num_ip_entries++;
    }

    // Copy and store the IP in network format
//    memcpy(&link->n_public_ip, &ip_addr, sizeof(uint32_t));

    if ( weight > 0 ) {
        link->dn_weight = weight;
    } else {
        link->dn_weight = 1;
    }

    // Copy and store the IP in presentation format
    setLinkIp_p(link, p_ip);

    link->data_port = data_port;

    // Copy the static network name (eg. sprint, verizon)
    strncpy(link->network, network, sizeof(link->network));

    // Add to the list of links
    gw->head_link = addLink(gw->head_link, link);

    // Punch a hole in the firewall for this IP 
    //iptables("A", "INPUT", "udp", link->p_ip, 8080);

#ifdef WITH_MYSQL
    // Write link status to the database
    gw_update_link(gw, link);
#endif

    return SUCCESS;
} // End function int addGwLink()

/*
 * CHANGE GW STATE
 */
void changeGwState(struct wigateway* gw, gw_state_t state)
{
    assert(gw != 0);

    if(gw->state != state) {
        gw->state = state;
        time(&gw->last_state_change);
    }

#ifdef WITH_MYSQL    
    gw_update_status(gw);
#endif
}

/*
 * D U M P  W I C O N T R O L L E R
 *
 * A function to dump the current state of the wicontroller.
 *
 * Returns (void)
 *
 */
void dumpWicontroller() 
{
    GENERAL_MSG("\tWiController\n");
    GENERAL_MSG("\tpproxy deprecated...\n");
//    GENERAL_MSG("\tIP Address: %s\n", pproxy->p_controller_ip);
//    GENERAL_MSG("\tPort: %d\n", pproxy->h_controller_port);
//    GENERAL_MSG("\taddr->sin_family: %hu\n", pproxy->addr.sin_family);
//    GENERAL_MSG("\taddr->sin_port: %hu\n", pproxy->addr.sin_port);
//    GENERAL_MSG("\taddr->sin_addr.s_addr: %d\n", pproxy->addr.sin_addr.s_addr);
} // End function dumpWicontroller()


/*
 * D U M P  W I G A T E W A Y S
 * 
 * A function to dump the current state of the wigateways.
 *
 */
void dumpWigateways() 
{
    GENERAL_MSG("\n---------------------------------------------------------------------\n\n");
    GENERAL_MSG("List of WiGateways: %s\n\n", getTime());

    struct wigateway *curr_gw = head_gw;
    while (curr_gw != NULL) 
    {
        GENERAL_MSG("ID: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\t Node ID: %d\n", 
            curr_gw->id[0], curr_gw->id[1], curr_gw->id[2], curr_gw->id[3], curr_gw->id[4], curr_gw->id[5],
            curr_gw->node_id);
        GENERAL_MSG("Lease Begin (unix time): %d\n", curr_gw->lease_begin);
        GENERAL_MSG("Lease End (unix time): %d\n", curr_gw->lease_end);

        GENERAL_MSG("Private IP: %d:%s\n", curr_gw->n_private_ip, curr_gw->p_private_ip);

        GENERAL_MSG("Algorithm: ");

        switch(curr_gw->algo) 
        {
            case RR_CONN:
                GENERAL_MSG("RR_CONN\n");
                break;
            case RR_PKT:
                GENERAL_MSG("RR_PKT\n");
                break;
            case WRR_CONN:
                GENERAL_MSG("WRR_CONN\n");
                break;
            case WRR_PKT:
                GENERAL_MSG("WRR_PKT\n");
                break;
            case WRR_PKT_v1:
                GENERAL_MSG("WRR_PKT_v1\n");
                break;
            case WDRR_PKT:
                GENERAL_MSG("WDRR_PKT\n");
            case SPF:
                GENERAL_MSG("SPF\n");
                break;
            default:
                GENERAL_MSG("UNKNOWN\n");
                break;
        } 

        struct link* link = curr_gw->head_link;
        GENERAL_MSG("IP Entries: \n");
        dumpInterfaces(link, "  ");

        GENERAL_MSG("Number of usable interfaces: %d\n\n", curr_gw->num_interfaces);

        curr_gw = curr_gw->next;
    }

    GENERAL_MSG("---------------------------------------------------------------------\n\n");
} // End function dumpWigateways()


/*
 * S M A L L  D U M P  W I G A T E W A Y S
 * 
 * A function to dump the current state of the wigateways.
 *
 */
void smallDumpWigateways() 
{
    GENERAL_MSG("\n---------------------------------------------------------------------\n\n");
    GENERAL_MSG("Notification Received: List of WiGateways: %s\n\n", getTime());

    struct wigateway *curr_gw = head_gw;
    while (curr_gw != NULL) 
    {
        GENERAL_MSG("ID: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\t Node ID: %d\n", 
            curr_gw->id[0], curr_gw->id[1], curr_gw->id[2], curr_gw->id[3], curr_gw->id[4], curr_gw->id[5],
            curr_gw->node_id);
        GENERAL_MSG("Private IP: %s\n", curr_gw->p_private_ip);

        struct link* link = curr_gw->head_link;
        GENERAL_MSG("IP Entries: \n");

        dumpInterfaces(link, "  ");
		
        curr_gw = curr_gw->next;
        GENERAL_MSG("\n"); 
    }

    GENERAL_MSG("---------------------------------------------------------------------\n\n");
} // End function smallDumpWigateways()


/*
 * F I N D  F R E E  I P
 *
 * Returns (uint32_t)
 *      Success: an IP address in network (uint32_t) format
 *      Failure: -1
 *
 */	
uint32_t findFreeIp() 
{
	/* tmp_gw->n_private_ip = 33663168; 192.168.1.2 in network format */

	// Network Format, loop until you find a free address
    uint32_t host_start_addr = ntohl(dhcp_start_addr.sin_addr.s_addr);
    uint32_t test_ip;
    uint32_t net_test_ip;

    for (test_ip = host_start_addr; test_ip <= host_start_addr + dhcp_range; test_ip++) {
        net_test_ip = htonl(test_ip);

        if( searchWigatewaysByIP(net_test_ip) == NULL ) {
            char ip[20];
            inet_ntop(AF_INET, &net_test_ip, ip, 20);
            GENERAL_MSG("Dolling out IP: %s\n", ip);

			return net_test_ip;
		}
	}

    return FAILURE;
} // End function findFreeIp()

/*
 * F I N D  F R E E  P O R T
 *
 * Returns (int)
 *      Success: The port number (in host byte order)
 *      Failure: -1
 *
 */	
int findFreeFwdPort() 
{
    int curr_port = start_fwd_port;

	// Network Format
	// Loop until you find a free address
	while ( curr_port < end_fwd_port )
    {
		if ( searchWigatewaysByPort(curr_port) == NULL ) 
        {
			return curr_port;
		}
		else 
        {
            curr_port++;
		}
	}

    return FAILURE;
} // End function findFreeFwdPort()

/*
 * C O M P U T E   N O D E   I D
 *
 */
int computeNodeId(unsigned char* hw_addr, unsigned int len)
{
    int temp = 0;
    int total = 0;
    int i = 0;
    for (i = 0; i < len; ++i)
    {
        temp = 0;
        temp |= hw_addr[i];
        total += temp;
    } 

    return total;
}

/*
 * L E A S E   A V A I L A B L E
 *
 * Arguments ip and port must be in host byte order.
 * Set port=0 to ignore the port.  The forwarding ports are related
 * to the DMZ and are not fully supported anyway.
 *
 * Returns (int)
 *      1 if IP and port are available for use
 *      0 if either is already taken
 *
 */	
int leaseAvailable(uint32_t ip, unsigned short port) 
{
    uint32_t host_start_addr = ntohl(dhcp_start_addr.sin_addr.s_addr);

    // Check if the requested IP is within our DHCP range
    if( ip < host_start_addr || ip > host_start_addr + dhcp_range ) {
        return 0;
    }

    // Check if IP is in use
    if( searchWigatewaysByIP(htonl(ip)) != NULL ) {
        return 0;
    }

    // Check if port is in use
    if(port > 0 && searchWigatewaysByPort(port) != NULL ) {
        return 0;
    }

    return 1;
} // End function leaseAvailable()

/*
 * G R A N T  L E A S E
 *
 * Function to grant a wigateway an IP address
 *   
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int grantLease(struct wigateway *gw, int sockfd) 
{
    // We need to insert it into the linked list and initialize it's values
    gw->n_private_ip = findFreeIp();
    gw->fwd_port     = findFreeFwdPort();
    inet_ntop(AF_INET, &gw->n_private_ip, gw->p_private_ip, sizeof(gw->p_private_ip));
    time((time_t *)&gw->lease_begin);

    // 12 hour lease time 
    gw->lease_end	= gw->lease_begin + LEASE_TIME;
    
    pthread_mutex_lock(&scan_gw_mutex);
    if ( insertGateway(gw) < 0 )
    {
        DEBUG_MSG("insertGateway() failed");
        pthread_mutex_unlock(&scan_gw_mutex);
        return FAILURE;
    }
    pthread_mutex_unlock(&scan_gw_mutex);

    unsigned short n_node_id = htons(gw->node_id);
    
    struct contchan_response response;
    response.type = htons(CONTCHAN_RESPONSE);
    response.priv_ip = gw->n_private_ip;
    response.lease_time = LEASE_TIME;
    response.node_id = n_node_id;

    int rtn = send(sockfd, &response, sizeof(response), 0);
    if(rtn < 0) {
        ERROR_MSG("send failed");
        return FAILURE;
    } else if(rtn < sizeof(response)) {
        DEBUG_MSG("send not completed");
        return FAILURE;
    }

    return SUCCESS;
} // End function grantLease()


/*
 * R E N E W  L E A S E
 *
 * Function to renew a wigateway's lease 
 *   
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int renewLease(struct wigateway * gw, int sockfd) 
{
    // We need to insert it into the linked list and initialize it's values
    time((time_t *)&gw->lease_begin);

    // 12 hour lease time 
    gw->lease_end	= gw->lease_begin + LEASE_TIME;

    unsigned short n_node_id = htons(gw->node_id);

    struct contchan_response response;
    response.type = htons(CONTCHAN_RESPONSE);
    response.priv_ip = gw->n_private_ip;
    response.lease_time = LEASE_TIME;
    response.node_id = n_node_id;

    int rtn = send(sockfd, &response, sizeof(response), 0);
    if(rtn < 0) {
        ERROR_MSG("send failed");
        return FAILURE;
    } else if(rtn < sizeof(response)) {
        DEBUG_MSG("send not completed");
        return FAILURE;
    }

    return SUCCESS;
} // End function renewLease()

/*
 * R E S T O R E   L E A S E
 *
 * Restores a lease that was previously given to a gateway.
 * (This needs to happen when the controller is restarted, but the
 * gateways do not know to request a new lease.)
 *   
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int restoreLease(struct wigateway *gw, uint32_t ip, unsigned short port) 
{
    // We need to insert it into the linked list and initialize it's values
    gw->n_private_ip = ip;
    inet_ntop(AF_INET, &gw->n_private_ip, gw->p_private_ip, sizeof(gw->p_private_ip));
    gw->fwd_port     = htons(port);
    
    // 12 hour lease time 
    time((time_t *)&gw->lease_begin);
    gw->lease_end	= gw->lease_begin + LEASE_TIME;

    // TODO: Pick an algorithm for it
    gw->algo = WRR_CONN;

    pthread_mutex_lock(&scan_gw_mutex);
    if ( insertGateway(gw) < 0 )
    {
        DEBUG_MSG("insertGateway() failed");
        pthread_mutex_unlock(&scan_gw_mutex);
        return FAILURE;
    }
    pthread_mutex_unlock(&scan_gw_mutex);

    return SUCCESS;
} // End function grantLease()


/*
 * H A N D L E  C O N T R O L  P A C K E T S
 * 
 * Function to handle any packet received on the control channel.
 *
 * Returns (int)
 *      Success: The packet type
 *      Failure: -1
 *
 */
int handleControlPackets(int wigateway_sock)
{
    char   		    packet[MTU];
    int             buf_len = sizeof(packet);
    int             num_bytes_received;

    struct timeval timeout;
    timeout.tv_sec  = CONTROL_CHANNEL_TIMEOUT;
    timeout.tv_usec = 0;

    int res = setsockopt(wigateway_sock, SOL_SOCKET, SO_RCVTIMEO, 
            (char *)&timeout, sizeof(timeout));
    if(res < 0) {
        ERROR_MSG("setsockopt SO_RCVTIMEO failed");

        // If we fail to set a timeout, the recv() call can block forever,
        // which disables control channel functionality.  This has happened
        // before, and it can go undetected for days.  Failure of setsockopt
        // seems unlikely.
        return FAILURE;
    }

    // Zero out the packet array that we will store the incoming packet in
    memset(packet, 0, sizeof(packet));

    num_bytes_received = recv(wigateway_sock, packet, buf_len, 0);
    if(num_bytes_received < 0) {
        if(errno == EAGAIN) {
            // If this happens often (say, more than once a minute), the
            // control channel will become unresponsive.  Check if the gateway
            // code has a bug that causes it to open a connection but not send
            // anything or consider using select() to handle multiple
            // simultaneous connections so that one failing gateway does not
            // impact the others.
            DEBUG_MSG("Warning: recv() timed out after %d seconds", 
                    CONTROL_CHANNEL_TIMEOUT);
        } else {
            ERROR_MSG("recv failed");
        }
        return FAILURE;
    } else if(num_bytes_received < sizeof(struct contchan_request)) {
        DEBUG_MSG("unusually small packet from gateway");
        return FAILURE;
    } else {
        uint16_t n_type;
        unsigned short h_type;

        // First two bytes should be control channel packet type
        memcpy(&n_type, packet, 2);
        h_type = ntohs(n_type);

        struct contchan_request* request = (struct contchan_request*)packet;

        switch(h_type) 
        {
            case CONTCHAN_REQUEST:
                processLease(wigateway_sock, packet, num_bytes_received, wigateway_sock);
                dumpWigateways();
                break;
            case CONTCHAN_NOTIFICATION:
                updateWigateway(packet, num_bytes_received);
                smallDumpWigateways();
                break;
            case CONTCHAN_SHUTDOWN:
                handleShutdownMessage(request);
                //dumpWigateways();
                break;
            default:
                DEBUG_MSG("Received unknown packet type on control channel, ignoring");
                break;
        }

        return h_type;
    }
} // End function handleControlPackets()


/*
 * I N S E R T  G A T E W A Y 
 *
 * Function to insert a gateway into the linked list of wigateways.
 * 
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int insertGateway(struct wigateway *gw) 
{
	// Always insert at the tail
	if ( head_gw == NULL ) 
	{
		head_gw  = gw;
		tail_gw  = gw;
		gw->next = NULL;
		gw->prev = NULL;
	}
	else 
	{
		gw->next = NULL;
		gw->prev = tail_gw;
		tail_gw->next = gw;
        tail_gw = gw;
	}
    
    return SUCCESS;
} // End function insertGateway()

/*
 * HANDLE SHUTDOWN MESSAGE
 */
void handleShutdownMessage(struct contchan_request* request)
{
    assert(request != 0);

    struct wigateway* gw = searchWigatewaysByID(request->unique_id);
    if(gw) {
        changeGwState(gw, GW_STATE_OFFLINE);
    }

    if ( removeWigateway(request->unique_id) < 0 ) {
        DEBUG_MSG("removeWigateway() failed");
    }
}

/*
 * U P D A T E  W I G A T E W A Y
 *
 * Function to update a gateway's respective information
 * 
 * Returns (void)
 */
void updateWigateway(char *packet, int sizeofpacket)
{
    struct wigateway *gateway;

    struct contchan_request* __restrict__ request = (struct contchan_request*)packet;
    unsigned int curr_packet_index = sizeof(struct contchan_request);
    
    gateway = searchWigatewaysByID(request->unique_id);
    if(gateway) {
		gateway->num_interfaces = 0;
		gateway->num_ip_entries = 0;

        // Mark all links dead, then make ACTIVE only those in the notification
        struct link* link = gateway->head_link;
        while(link) {
            link->state = DEAD;
            link = link->next;
        }

		while ( (curr_packet_index + sizeof(struct contchan_link)) <= sizeofpacket ) {
			int 	found = 0;

            // This pointer is certain to be valid, since we verified that the
            // packet is at least long enough to contain this structure.
            struct contchan_link* __restrict__ cc_link = (struct contchan_link*)(packet + curr_packet_index);
            curr_packet_index += sizeof(struct contchan_link);

            struct link* curr_link = gateway->head_link;
            while(curr_link) {
				if ( strncmp(curr_link->ifname, cc_link->ifname, IFNAMSIZ) == 0 ) {
                    // Fill the hole with the old public IP
                    iptables("D", "INPUT", "udp", curr_link->p_ip, 8080);

                    //Punch a hole with the updated IP
                    iptables("A", "INPUT", "udp", curr_link->p_ip, 8080);
                    
                    // If the gateway is behind a nat, then it sends us the
                    // wrong IP address.  We only use the notification IP
                    // address when a new link is added (we have no better
                    // information at that time).  Otherwise, we can discover
                    // the public IP address from the first ping packet sent
                    // out that interface.
                    //setLinkIp_n(curr_link, cc_link->pub_ip);

                    // Copy the static network name (eg. sprint, verizon)
                    strncpy(curr_link->network, cc_link->network, sizeof(curr_link->network));

					curr_link->state        = ntohs(cc_link->state);
					curr_link->dn_weight    = ntohs(cc_link->weight);

					if(curr_link->state == ACTIVE) {
						gateway->num_interfaces++;
						gateway->num_ip_entries++;
					}

#ifdef WITH_MYSQL
                    // Write link status to the database
                    gw_update_link(gateway, curr_link);
#endif

                    // Set found to one if we already have this interface in
                    // our list
					found = 1;
                    break;
				}

				curr_link = curr_link->next;
			}

            // If the gateway has sent us a new link, add it
			if ( !found ) {
                char p_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, cc_link->pub_ip, p_ip, sizeof(p_ip));
        
                unsigned short h_state = ntohs(cc_link->state);
                unsigned short h_weight = ntohs(cc_link->weight);
                unsigned short h_link_id = ntohs(cc_link->link_id);

                /* First try the default data port, which will work for most
                 * cases.  Update later if we receive a nat punch from a
                 * different port. */
                unsigned short n_data_port = htons(WIROVER_PORT);

				addGwLink(gateway, cc_link->ifname, p_ip, n_data_port, 
                        cc_link->network, h_state, h_weight, h_link_id, 1);
			}
		}
        
        // After all of the links have been processed, print the gateway list
        smallDumpWigateways();
	}
    else 
    {
        DEBUG_MSG("Notification received, but gateway ID unrecognized");
    }
} // End function void updateWigateway()


/*
 * P R O C E S S  L E A S E
 *
 * Function to process a request from a wigateway
 *
 * Returns (void)
 *
 */
void processLease(int sockfd, char * packet, int sizeofpacket, int wigateway_sock) 
{
    struct wigateway *gateway = createGateway();

    struct contchan_request* __restrict__ request = (struct contchan_request*)packet;
    unsigned int curr_packet_index = sizeof(struct contchan_request);

    // Copy the gateway's unique id
    memcpy(&gateway->id, request->unique_id, sizeof(gateway->id));

    // The node ID is computed based on the MAC address of the gateway's primary link
    gateway->node_id = computeNodeId(gateway->id, ETH_ALEN);

	gateway->algo = ntohs(request->algo);

    struct wigateway *old_gw;
	if ( (old_gw = searchWigatewaysByID(gateway->id)) == NULL ) 
	{
		// We've never seen wigateway gw before, give it an offer
		grantLease(gateway, sockfd);
	}
    else
    {
        // Renew Lease
        removeWigateway(old_gw->id);
		grantLease(gateway, sockfd);
    }
    
    changeGwState(gateway, GW_STATE_ACTIVE);
    
    while( curr_packet_index + sizeof(struct contchan_link) <= sizeofpacket ) {
        char p_ip[INET6_ADDRSTRLEN];

        // This pointer is certain to be valid, since we verified that the
        // packet is at least long enough to contain this structure.
        struct contchan_link* __restrict__ cc_link = (struct contchan_link*)(packet + curr_packet_index);
        curr_packet_index += sizeof(struct contchan_link);
  
        inet_ntop(AF_INET6, cc_link->pub_ip, p_ip, sizeof(p_ip));

        unsigned short h_state = ntohs(cc_link->state);
        unsigned short h_weight = ntohs(cc_link->weight);
        unsigned short h_link_id = ntohs(cc_link->link_id);
                
        /* First try the default data port, which will work for most cases.
         * Update later if we receive a nat punch from a different port. */
        unsigned short n_data_port = htons(WIROVER_PORT);

        addGwLink(gateway, cc_link->ifname, p_ip, n_data_port,
                cc_link->network, h_state, h_weight, h_link_id, 0);
	}
} // End function processLease()


/*
 * R E M O V E  S T A L E  W I G A T E W A Y S
 *  
 * A function to remove all stale gateways
 *
 * Returns (void)
 * 
 */
void removeStaleWigateways()
{
	struct wigateway *curr = head_gw;
    time_t curr_time = time(0);
        
	// Loop through wigateway structures
	while( curr != NULL ) 
	{
        struct link *link;

		pthread_mutex_lock(&scan_gw_mutex);
            
        link = curr->head_link;
        while(link) {
            // Check for idle links that may have failed
            if((link->state == ACTIVE || link->state == STANDBY) &&
                    curr_time - link->last_packet_received >= LINK_ACTIVE_TIMEOUT) {
                link->state = INACTIVE;
#ifdef WITH_MYSQL
                gw_update_link(curr, link);
#endif
            }

            link = link->next;
        }

        if ((curr_time - curr->last_seen_pkt_time) >= GATEWAY_ACTIVE_TIMEOUT) {
            DEBUG_MSG("Setting node %d to INACTIVE", curr->node_id);
            changeGwState(curr, GW_STATE_INACTIVE);
            removeWigateway(curr->id);
        }

		pthread_mutex_unlock(&scan_gw_mutex);
        curr = curr->next;
    }
} 


/*
 * R E M O V E  W I G A T E W A Y
 *
 * Function to remove a wigateway struct from the linked list
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int removeWigateway(unsigned char *id)
{
	struct wigateway *curr = head_gw;

	// Loop through wigateway structures
	while( curr != NULL ) 
	{
		// We found a match
		if ( curr->id[0] == id[0] && curr->id[1] == id[1] && curr->id[2] == id[2] 
             && curr->id[3] == id[3] && curr->id[4] == id[4] && curr->id[5] == id[5] )
		{
            // Remove this gateway
            if ( curr == head_gw && curr == tail_gw )
            {
                head_gw = NULL;
                tail_gw = NULL;
            }
            else if ( curr == head_gw )
            {
                curr->next->prev = NULL;
                head_gw = curr->next;
            }
            else if ( curr == tail_gw )
            {
                curr->prev->next = NULL;
                tail_gw = curr->prev;
            }
            else
            {
                curr->prev->next = curr->next;
                curr->next->prev = curr->prev;
            }

            // Free the link sub structures
            while(curr->head_link) {
                struct link* tmp = curr->head_link;
                
                // Fill the hole back up in the firewall
                iptables("D", "INPUT", "udp", tmp->p_ip, 8080);
                
                curr->head_link = tmp->next;
                free(tmp);
            }

            free(curr); 
            smallDumpWigateways();
            
            return SUCCESS;
		}

		curr = curr->next;
	}
    
    return FAILURE;
} // End function int removeWigateway()


/*
 * S E A R C H  W I G A T E W A Y S  B Y  N O D E  I D
 * 
 * Function to iterate through the wigateways and return a matching one
 *
 * Returns (struct wigateway)
 *      Success: a wigateway structure
 *      Failure: NULL
 */
struct wigateway *searchWigatewaysByNodeID(int node_id) 
{
	struct wigateway *curr = head_gw;

	// Loop through wigateway structures
	while( curr != NULL ) 
	{
		// We found a match
		if ( curr->node_id == node_id )
		{
			return curr;
		}
        else
        {
            curr = curr->next;
        }
	}
	
	return NULL;
} // End function struct wigateway *searchWiGatewaysByIdNodeID


/*
 * S E A R C H  W I G A T E W A Y S  B Y  I D
 * 
 * Function to iterate through the wigateways and return a matching one
 *
 * Returns (struct wigateway)
 *      Success: a wigateway structure
 *      Failure: NULL
 */
struct wigateway *searchWigatewaysByID(unsigned char *id) 
{
	struct wigateway *curr = head_gw;

	// Loop through wigateway structures
	while( curr != NULL ) 
	{
		// We found a match
		if ( curr->id[0] == id[0] && curr->id[1] == id[1] && curr->id[2] == id[2] 
             && curr->id[3] == id[3] && curr->id[4] == id[4] && curr->id[5] == id[5] )
		{
			return curr;
		}
        else
        {
            curr = curr->next;
        }
	}
	
	return NULL;
} // End function struct wigateway *searchWiGatewaysById


/*
 * S E A R C H  W I G A T E W A Y S  B Y  I P
 * 
 * Function to iterate through the wigateways and return a matching one
 * based on private ip
 *
 * Returns (struct wigateway)
 *      Success: a wigateway structure
 *      Failure: NULL
 */
struct wigateway *searchWigatewaysByIP(uint32_t gw_private_ip) 
{
	struct wigateway * curr = head_gw;

	// Loop through wigateway structures
	while( curr != NULL ) 
	{
		// We found a match
		if ( curr->n_private_ip == gw_private_ip )
		{
			return curr;
		}

		curr = curr->next;
	}
	
	return NULL;
} // End function struct wigateway *searchWigatewaysByIP()


/*
 * S E A R C H  W I G A T E W A Y S  B Y  P U B  I P
 *
 * Function to iterate through the wigateways and return a matching one by 
 * public ip address matching
 *
 * TODO: This function should be deprecated in favor of methods that
 * are compatible with IPv6.
 *
 * Returns (nint)
 *      Success: struct wigateway *
 *      Failure: NULL
 *
 */
struct wigateway *searchWigatewaysByPubIP(uint32_t public_ip)
{
    struct wigateway * curr = head_gw;

    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &public_ip, p_ip, sizeof(p_ip));

    // Loop through wigateway structures
    while( curr != NULL ) {
        struct link* link = searchLinksByIp(curr->head_link, p_ip);
        if(link) {
            return curr;
        }

        curr = curr->next;
    }

    return NULL;
} // End function searchWigatewaysByPubIP()

/*
 * S E A R C H  W I G A T E W A Y S  B Y  P O R T
 * 
 * Function to iterate through the wigateways and return a matching one
 *
 * Returns (struct wigateway)
 *      Success: a wigateway structure
 *      Failure: NULL
 */
struct wigateway *searchWigatewaysByPort(short port) 
{
	struct wigateway *curr = head_gw;

	// Loop through wigateway structures
	while( curr != NULL ) 
	{
		// We found a match
		if ( curr->fwd_port == port )
		{
			return curr;
		}

		curr = curr->next;
	}
	
	return NULL;
} // End function struct wigateway *searchWiGatewaysByPort


/*
 * C L E A N U P  W I G A T E W A Y S 
 *
 * A function to loop throught the wigateway linked list and free
 * each wigateway
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int cleanupWigateways()
{
    GENERAL_MSG("Cleaning up WiGateway structures . . . ");
	struct wigateway *curr_gw;

    while( (curr_gw = head_gw) != NULL ) 
    {
        // Free the link sub structures
        while(curr_gw->head_link) {
            struct link* tmp = curr_gw->head_link;
            
            // Fill the hole back up in the firewall
            iptables("D", "INPUT", "udp", tmp->p_ip, 8080);
            
            curr_gw->head_link = tmp->next;
            free(tmp);
        }

        head_gw = curr_gw->next; 
        free(curr_gw);
    } 

    GENERAL_MSG("Done.\n");
    return SUCCESS;
} // End function cleanupWigateways()

/*
 * Create the control channel thread which listens for notifications from
 * gateways and keeps the gateway list up-to-date.
 */
int createContChanThread()
{
    pthread_attr_t attr;

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    if(pthread_create(&cont_chan_thread, &attr, contChanThreadFunc, 0) != 0) {
        ERROR_MSG("pthread_create failed");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);

    return SUCCESS;
}

/*
 * Wait for control channel thread to exit.
 */
int destroyContChanThread()
{
    GENERAL_MSG("Destroying scanGwThread . . . ");
    if(pthread_join(cont_chan_thread, 0) != 0) {
        ERROR_MSG("pthread_join failed");
        return FAILURE;
    }

    GENERAL_MSG("Done.\n");
    return SUCCESS;
}

/*
 * Control channel thread main function.  Listens on the control channel port
 * for lease requests and notifications of link state changes.
 */
void *contChanThreadFunc(void *arg)
{
    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGALRM);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);

    // Block common signals so that they do not interrupt our socket functions.
    pthread_sigmask(SIG_BLOCK, &sigmask, 0);

    int skfd = createContChanSocket();
    if(skfd < 0) {
        DEBUG_MSG("Fatal error: createContChanSocket() failed");
        exit(EXIT_FAILURE);
    }

    while(!getQuitFlag()) {
        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(skfd, &readset);

        struct timeval timeout;
        timeout.tv_sec  = CLEAN_GATEWAYS_INTERVAL;
        timeout.tv_usec = 0;

        int ready = select(skfd + 1, &readset, 0, 0, &timeout);
        if(ready < 0) {
            ERROR_MSG("select failed");
        } else if(ready > 0 && FD_ISSET(skfd, &readset)) {
            struct sockaddr_storage client_addr;
            socklen_t client_addr_len = sizeof(client_addr);

            int client_skfd = accept(skfd, (struct sockaddr *)&client_addr, 
                    &client_addr_len);
            if(client_skfd < 0) {
                ERROR_MSG("accept failed");
            } else {
                if(handleControlPackets(client_skfd) < 0) {
                    DEBUG_MSG("handleControlPackets() failed");
                }
                close(client_skfd);
            }
        }
        
        removeStaleWigateways();
    }

    pthread_exit(0);
}

/*
 * S E T  F O R W A R D  P O R T S
 *
 * Returns (void)
 */
void setForwardPorts(short start, short end)
{
    start_fwd_port = start;
    end_fwd_port = end;
} // End function void setForwardPorts()

