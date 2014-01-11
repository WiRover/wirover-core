/*
 * C O N T  C H A N . C
 *
 * This file contains the necessary functions to operate the WiRover's
 * control channel from the WiGateway.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/tcp.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "../common/tunnelInterface.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/utils.h"
#include "../common/contChan.h"
#include "../common/myssl.h"
#include "selectInterface.h"

int createSocket();
int createUdpSocket(int n_ip, short n_port);
int createControlChannel(struct tunnel * tun);
int connectControlChannel();
int setInterfaceIp(char * n_assigned_ip);
int sendRequest(int sockfd, unsigned short type, struct link* head_link);

static char local_buf[MAX_LINE];
static struct wicontroller proxy, *pproxy;
static unsigned char unique_id[ETH_ALEN];
static short node_id;

// IPSEC information
static ipsec_req_t ipsr;
BIO *ssl_conn;


/*
 * O P E N  S S L  C O N T R O L  C H A N N E L 
 */ 
BIO *openSSLControlChannel(char *device)
{
    char port[10];
    sprintf(port, "%o", (unsigned int)CONTROL_PORT);
    init_OpenSSL();     

    char ssl_conn_str[50];
    strcat(ssl_conn_str, getControllerIP());
    strcat(ssl_conn_str, ":");
    strcat(ssl_conn_str, port);

    ssl_conn = BIO_new_connect(ssl_conn_str);

    if ( ! ssl_conn )
    {
        DEBUG_MSG("Error creating connection BIO");
        return NULL;
    }

    if ( BIO_do_connect(ssl_conn) < 0 )
    {
        DEBUG_MSG("Error connecting to controller BIO");
        return NULL;
    }

    return ssl_conn;
} // End function BIO *openSSLControlChannel


/*
 * C L O S E  S S L  C O N T R O L  C H A N N E L
 */
void closeSSLControlChannel(BIO *bio)
{
    /* To resuse the connection, use this line */
    BIO_reset(bio);

    /* To free it from memory, use this line */
    BIO_free_all(bio);
} // End function void closeSSLControlChannel()


/*
 * O P E N  C O N T R O L  C H A N N E L
 *
 * Function to open up the control channel,
 *
 * Returns (int): 
 *      Success: A socket fd
 *      Failure: -1
 *
 */
int openControlChannel(char *device) 
{
    int socket, rval;

    // Create the socket to connect to the server   
    if ( (socket = createSocket()) < 0 ) 
    { 
        DEBUG_MSG("createSocket() failed");
        return FAILURE;
    }

    if(device != NULL)
    {
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(struct ifreq));

        /*
        memset(&myAddr, 0, sizeof(struct sockaddr_in));
        myAddr.sin_family      = AF_INET;
        myAddr.sin_port        = htons((unsigned short)CONTROL_PORT);
        myAddr.sin_addr.s_addr = htonl(INADDR_ANY);

        if(bind(socket, (struct sockaddr *)&myAddr, sizeof(struct sockaddr_in)) < 0)
        {
            ERROR_MSG("bind() failed");
            close(socket);
            return FAILURE;
        }
    
        // TODO: Weird phenomenon, when socket is bound, lease packets don't seem to
        // be getting through
        if(setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, device, IFNAMSIZ) < 0)
        {
            close(socket);
            return FAILURE;
        }
        */

        if(setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, device, IFNAMSIZ) < 0)
        {
            ERROR_MSG("setsockopt(SO_REUSEADDR) failed");
            close(socket);
            return FAILURE;
        }

/*
        if(setsockopt(socket, SOL_SOCKET, SO_DONTROUTE, device, IFNAMSIZ) < 0)
        {
            ERROR_MSG("setsockopt(SO_DONTROUTE) failed");
            close(socket);
            return FAILURE;
        }
*/
    }

    if ( (rval = connectControlChannel(socket)) < 0 )
    {
        DEBUG_MSG("connectControlChannel() failed");
        close(socket);
        return FAILURE;
    }

    return socket;
} // End function int openControlChannel()


/*
 * C R E A T E  S O C K E T
 *
 * Function to create a socket
 *
 * Returns (int):
 *      Success: A socket fd
 *      Failure: -1
 *
 */
int createSocket() 
{
    int sockfd;
    
    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        ERROR_MSG("Error creating socket.");
        return FAILURE;
    }

    if ( USE_IPSEC )
    {
        if ( setIPSec(ipsr, sockfd) < 0 )
        {
            DEBUG_MSG("setIPSec() failed");
            return FAILURE;
        }
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if ( setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) < 0 )
    {
        ERROR_MSG("setsockopt() SO_RCVTIMEO failed");
    }

    return sockfd;
} // End function createSocket() 


/*
 * C O N N E C T  C O N T R O L  C H A N N E L
 *
 * Function to connect the control channel (complete the three-way
 * TCP handshake)
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int connectControlChannel(int socket)
{
    int rval;

    // Put the address of proxy into pproxy
    pproxy = &proxy; 

    // Fill the variables
    pproxy->h_controller_port 	= CONTROL_PORT; 
    pproxy->n_controller_port 	= htons(CONTROL_PORT);
    pproxy->addr.sin_family		= AF_INET;
    pproxy->addr.sin_port		= htons(CONTROL_PORT);

    char cont_ip[INET_ADDRSTRLEN];
    strncpy(cont_ip, (char *)getControllerIP(), sizeof(cont_ip));
    inet_pton(AF_INET, cont_ip, &pproxy->n_controller_ip);
    inet_pton(AF_INET, cont_ip, &pproxy->addr.sin_addr);
	
    // Connect the client to the server
    if( (rval = connect(socket, (struct sockaddr *) &pproxy->addr, sizeof(pproxy->addr))) < 0)
    {
        ERROR_MSG("connect() failed");
        return FAILURE;
    }

    return SUCCESS;
} // End function int connectControlChannel()


/*
 * G E T  L E A S E
 *
 * Function to get a local IP address for the virtual tunnel device
 * from the controller
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int getLease()
{
    int           rtn;
    int           socket;
    struct link   *lease_ife;
    int           retval = FAILURE;
    //struct ifreq  temp;

    const unsigned packet_size = sizeof(struct contchan_response);
    char packet[packet_size];
    
    lease_ife = selectInterface(WRR_PKT, 0, 0);

    if ( lease_ife == NULL ) 
    {
        DEBUG_MSG("selectInterface() failed");
        return FAILURE;
    }

    sprintf(local_buf, "using interface (%s) . . . ", lease_ife->ifname);
    DEBUG_MSG(local_buf);

    // TODO: Get rid of hack
    addRoute(getControllerIP(), 0, (lease_ife->has_gw ? lease_ife->gw_ip : 0), 
            lease_ife->ifname);

    if( (socket = openControlChannel(lease_ife->ifname)) < 0)
    {
        DEBUG_MSG("openControlChannel() failed");
        return FAILURE;
    }

    /*
    if(internalIFGetMAC(&temp) == SUCCESS)
    {
        setUniqueID((unsigned char *)temp.ifr_hwaddr.sa_data);
    }
    else
    {
        DEBUG_MSG("internalIFGetMAC() failed");
        return FAILURE;
    }
    */

    if(sendRequest(socket, CONTCHAN_REQUEST, head_link__) == FAILURE) {
        goto close_socket;
    }

    // Receive an Address
    rtn = recv(socket, packet, packet_size, 0);
    if(rtn < 0) {
        ERROR_MSG("recv() failed");
        goto close_socket;
    } else if(rtn < packet_size) {
        DEBUG_MSG("Response to DHCP request was too short");
        goto close_socket;
    }

    struct contchan_response* response = (struct contchan_response*)packet;
    unsigned short h_type = ntohs(response->type);

    if(h_type != CONTCHAN_RESPONSE) {
        DEBUG_MSG("Response to DHCP request was of the wrong type");
        goto close_socket;
    }

    // We assume the tunnel will always use IPv4
    char p_priv_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &response->priv_ip, p_priv_ip, sizeof(p_priv_ip));
    setTunLocalIP(p_priv_ip);
            
    unsigned short h_node_id = ntohs(response->node_id);
    setNodeID(h_node_id);
    
    sprintf(local_buf, "Tunnel Received IP address: %s, Node ID: %d from Controller.", p_priv_ip, h_node_id);
    DEBUG_MSG(local_buf);
    STATS_BANNER(local_buf);
	
    retval = SUCCESS;

    // TODO: Get rid of hack
    //delGWRoute(getControllerIP(), "255.255.255.255", "0.0.0.0", lease_ife->name);

close_socket:
    if(close(socket) < 0) {
        ERROR_MSG("close() failed");
    }

    return retval;
} // End function getLease()


/*
 * G E T  N O D E  I D
 */
short getNodeID()
{
    return node_id;
} // End function int getNodeID()


/*
 * S E T  N O D E  I D
 */
void setNodeID(int id)
{
    node_id = id;
} // End function void setNodeID()


/*
 * G E T  U N I Q U E  I D
 */
unsigned char *getUniqueID()
{
    return unique_id;
} // End function getUniqueId()


/*
 * S E T  U N I Q U E  I D
 */
void setUniqueID(unsigned char *mac_addr)
{
    memcpy(unique_id, mac_addr, sizeof(unique_id));
} // End function void setUniqueID()


/*
 * N O T I F Y  C O N T R O L L L E R                     
 *
 * Function to notify the controller that an interface has
 * either gone up or down (either way it sends a cumulative list
 * of interfaces that are on this machine with the state
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int notifyController()
{
    int 		        rtn;
    struct link         *send_ife;
    uint32_t            tunPrivIP = getTunPrivIP();
    int                 retval = FAILURE;

    // Copy in bytes 2-7 with the unique_id
    unsigned char *unique_id = getUniqueID();

    if ( unique_id == NULL ) 
    {
        // Shouldn't happen, but will cause segfault if it does
        return FAILURE;
    }

    if ( tunPrivIP == 0 )
    {
        // Do not send a notify unless we have a lease already
        return FAILURE;
    }

    send_ife = selectInterface(WRR_PKT, 0, 0);
    dumpInterfaces(head_link__, "");

    if ( send_ife == NULL ) 
    {
        ERROR_MSG("selectInterface() returned NULL");
        ERROR_MSG("No interface to send notify to controller since all are inactive");
        return FAILURE;
    }
    
    DEBUG_MSG("Sending notify to controller using interface %s (%s)",
            send_ife->ifname, send_ife->network);

    // TODO: Get rid of hack
    addRoute(getControllerIP(), 0, (send_ife->has_gw ? send_ife->gw_ip : 0),
            send_ife->ifname);

    if( (send_ife == NULL) ) 
    {
        DEBUG_MSG("selectInterface() failed");
        /*
        if( data != NULL ) 
        {
            free(data);
        }
        */
        return FAILURE;
    }

    int socket;
    
    if ( (socket = openControlChannel(send_ife->ifname)) < 0 ) {
        DEBUG_MSG("openControlChannel() failed.");
        return FAILURE;
    }

    rtn = sendRequest(socket, CONTCHAN_NOTIFICATION, head_link__);
    if(rtn == FAILURE) {
        DEBUG_MSG("sendRequest failed");
    } else {
        retval = SUCCESS;
    }
    
    if ( close(socket) < 0 ) {
        ERROR_MSG("close() failed");
    }

    // TODO: Get rid of hack
    //delGWRoute(getControllerIP(), "255.255.255.255", "0.0.0.0", send_ife->name);

    return retval;
} // End function int notifyController() 


/*
 * S H U T D O W N  C O N T  C H A N
 */
int shutdownContChan()
{
    GENERAL_MSG("Shutting down control channel . . . ");
    int     rtn;
    int     retval;

    struct link *ife = selectInterface(WRR_PKT, 0, 0);
    if( !ife )
    {
        DEBUG_MSG("selectInterface() failed");
        return FAILURE;
    }
    else
    {
        sprintf(local_buf, "using interface: (%s) . . . ", ife->ifname);
        GENERAL_MSG(local_buf);
    }

    // TODO: Get rid of hack
    addRoute(getControllerIP(), 0, (ife->has_gw ? ife->gw_ip : 0), 
            ife->ifname);

    int socket; 
    if ( (socket = openControlChannel(ife->ifname)) < 0 )
    {
        DEBUG_MSG("openControlChannel() failed\n");
        // TODO: Get rid of hack
        //delGWRoute(getControllerIP(), "255.255.255.255", "0.0.0.0", ife->name);
        return FAILURE;
    }

    rtn = sendRequest(socket, CONTCHAN_SHUTDOWN, 0);
    if(rtn == FAILURE) {
        // TODO: Get rid of hack
        //delGWRoute(getControllerIP(), "255.255.255.255", "0.0.0.0", ife->name);
        DEBUG_MSG("sendRequest failed");
    } else {
        retval = SUCCESS;
    }

    if ( close(socket) < 0 ) {
        ERROR_MSG("close() failed");
    }

    // TODO: Get rid of hack
    //delGWRoute(getControllerIP(), "255.255.255.255", "0.0.0.0", ife->name);

    return retval;
} // End function int shutdownContChan()

/*
 * SEND REQUEST
 *
 * Sends a control channel request message.  Possible types are
 * CONTCHAN_REQUEST, CONTCHAN_NOTIFY, and CONTCHAN_SHUTDOWN.  For the shutdown
 * message, head_link should be set to null.  This will prevent sendRequest
 * from attempting to traverse the list of links.
 */
int sendRequest(int sockfd, unsigned short type, struct link* head_link)
{
    struct contchan_request request;
    struct contchan_link    link;
    unsigned int            packet_size;
    char*                   packet = 0;
    unsigned int            curr_packet_index = 0;

    unsigned short num_links = countValidLinks(head_link);

    memset(&request, 0, sizeof(struct contchan_request));
    request.type = htons(type);
    memcpy(request.unique_id, getUniqueID(), sizeof(request.unique_id));
    request.algo = htons((uint16_t)getRoutingAlgorithm());
    request.num_links = htons(num_links);

    packet_size = sizeof(struct contchan_request) + num_links * sizeof(struct contchan_link);
    packet = malloc(packet_size);

    // Pack in the request header
    memcpy(packet, &request, sizeof(struct contchan_request));
    curr_packet_index += sizeof(struct contchan_request);

    struct link* ife = head_link;
    while(ife) {
        // If the IP address is bad, then continue to next interface
        if ( ife->p_ip[0] == 0 ) {
            ife = ife->next;
            continue;
        }

        memset(&link, 0, sizeof(struct contchan_link));
        memcpy(link.ifname, ife->ifname, sizeof(link.ifname));
        memcpy(link.pub_ip, ife->n_ip, sizeof(link.pub_ip));
        readNetworkName(ife->ifname, ife->network, sizeof(ife->network));
        strncpy(link.network, ife->network, sizeof(link.network));
        link.state = htons(ife->state);
        link.weight = htons(ife->dn_weight);
        link.link_id = htons(ife->id);

        // Pack in the link information
        memcpy(packet + curr_packet_index, &link, sizeof(struct contchan_link));
        curr_packet_index += sizeof(struct contchan_link);

        ife = ife->next;
    }

    // Send our data
    int rtn = send(sockfd, packet, packet_size, 0);
    free(packet);

    if(rtn < 0) {
        ERROR_MSG("send() failed");
        return FAILURE;
    } else if(rtn < packet_size) {
        DEBUG_MSG("Request not completed");
        return FAILURE;
    }

    return SUCCESS;
}

// vim: set et ts=4 sw=4 cindent:

