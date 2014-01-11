/*
 * T U N N E L  I N T E R F A C E . C
 *
 * This file contains functions that create, initialize and destroy
 * the virtual tunnel interface.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "tunnelInterface.h"
#include "parameters.h"
#include "../common/debug.h"
#include "interface.h"
#include "link.h"
#include "utils.h"

static struct tunnel *tun = NULL;
static int localPort = -1;
static int TunnelFD = -1;
static uint32_t private_ip;
static char localIP[IFNAMSIZ];
static char remoteIP[IFNAMSIZ];
    
/*
 * D U M P  N E T W O R K  T U N  H D R 
 *
 * Returns (void)
 */
void dumpNetworkTunHdr(struct tunhdr *tun_hdr)
{
    printf("TUN_HDR\n");
    printf("\tseq_no:       %u\n", ntohl(tun_hdr->seq_no));
    printf("\tsend_ts:      %u\n", ntohl(tun_hdr->send_ts));
    printf("\trecv_ts:      %u\n", ntohl(tun_hdr->recv_ts));
    printf("\tservice:      %u\n", ntohl(tun_hdr->service));
    printf("\tclient_id:    %u\n", ntohs(tun_hdr->client_id));
    printf("\tnode_id:      %u\n", ntohs(tun_hdr->node_id));
    printf("\tlink_id:      %u\n", ntohs(tun_hdr->link_id));
    printf("\tlocal_seq_no: %u\n\n", ntohs(tun_hdr->local_seq_no));
    fflush(stdout);
} // End function void dumpNetworkTunHdr()

/*
 * D U M P  T U N  H D R 
 *
 * Returns (void)
 */
void dumpTunHdr(struct tunhdr *tun_hdr)
{
    printf("TUN_HDR\n");
    printf("\tseq_no:       %u\n", ntohl(tun_hdr->seq_no));
    printf("\tsend_ts:      %u\n", ntohl(tun_hdr->send_ts));
    printf("\trecv_ts:      %u\n", ntohl(tun_hdr->recv_ts));
    printf("\tservice:      %u\n", ntohl(tun_hdr->service));
    printf("\tclient_id:    %u\n", ntohs(tun_hdr->client_id));
    printf("\tnode_id:      %u\n", ntohs(tun_hdr->node_id));
    printf("\tlink_id:      %u\n", ntohs(tun_hdr->link_id));
    printf("\tlocal_seq_no: %u\n\n", ntohs(tun_hdr->local_seq_no));
    fflush(stdout);
} // End function void dumpTunHdr()


/*
 * G E T  T U N  L O C A L  P O R T
 */
int getTunLocalPort()
{
    return localPort;
} // End function int getTunLocalPort()


/*
 * S E T  T U N  L O C A L  P O R T
 */
int setTunLocalPort(int port)
{
    if ( port < 0 )
    {
        return FAILURE;
    }
    else
    {
        localPort = port;
        return SUCCESS;
    }
    return FAILURE;
} // End function int setTunLocalPort(int port)


/*
 * G E T  T U N  P R I V  I P 
 */
uint32_t getTunPrivIP()
{
   return private_ip; 
} // End function uint32_t getTunPrivIP()


/*
 * S E T  T U N  P R I V  I P
 */
int setTunPrivIP(int i)
{
    if ( i < 0 )
    {
        return FAILURE;
    }
    else
    {
        private_ip = (uint32_t)i;
        return SUCCESS;
    }
    return FAILURE;
} // End function int setTunPrivIP(int i)


/*
 * G E T  T U N  L O C A L  I P
 */
char *getTunLocalIP()
{
    return localIP;
} // End function char *getTunLocalIP()


/*
 * S E T  T U N  L O C A L  I P
 */
int setTunLocalIP(char *i)
{
    if ( i == NULL )
    {
        return FAILURE;
    }
    else
    {
        memcpy(localIP, i, sizeof(localIP));
        return SUCCESS;
    }
    return FAILURE;
} // End function int setTunLocalIP(char *i)


/*
 * G E T  T U N  R E M O T E  I P
 */
char *getTunRemoteIP()
{
    return remoteIP;
} // End function char *getTunRemoteIP()


/*
 * S E T  T U N  R E M O T E  I P
 */
int setTunRemoteIP(char *i)
{
    if ( i == NULL )
    {
        return FAILURE;
    }
    else
    {
        memcpy(remoteIP, i, sizeof(localIP));
        return SUCCESS;
    }
    return FAILURE;
} // End function int setTunRemoteIP(char *i)


/*
 * G E T  T U N N E L 
 */
struct tunnel *getTunnel()
{
    return tun;
} // End functionstruct tunnel *getTunnel()

/*
 * G E T  T U N N E L  D E S C R I P T O R
 */
int getTunnelDescriptor()
{
    return TunnelFD;
} // End function int getTunnelDescriptor()


/*
 * S E T  T U N N E L  D E S C R I P T O R
 */
int setTunnelDescriptor(int value)
{
    if(value < 0)
    {
        return FAILURE;
    }
    else
    {
        TunnelFD = value;
        return SUCCESS;
    }
    return FAILURE;
} // End function int setTunnelDescriptor(int value)


/*
 * T U N N E L  A L L O C
 *
 * Function to allocate the tun device
 *
 * Returns (int):
 *      Success: tun file descriptor
 *      Failure: -1
 *
 */
static int tunnelAlloc(struct tunnel *tun)
{
    struct sockaddr_in *addr = NULL;
    struct ifreq ifr;
    int fd, err, sock;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) 
    {
        ERROR_MSG("open failed");
        goto failure;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
    *        IFF_TAP    - TAP device  
    *
    *        IFF_NO_PI - Do not provide packet information  
    */ 
    ifr.ifr_flags = IFF_TUN; 

    strncpy(ifr.ifr_name, "tun\%d", IFNAMSIZ);

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 )
    {
        ERROR_MSG("ioctl(TUNSETIFF) failed");
        goto failure;
    }

    strncpy(tun->name, ifr.ifr_name, sizeof(ifr.ifr_name));

    if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) 
    {
        ERROR_MSG("socket failed");
        goto failure;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(tun->localIP);
    //addr->sin_addr.s_addr = inet_addr("192.168.1.2");
    //setTunLocalIP(tun->localIP);

    uint32_t privIP;
    inet_pton(AF_INET, tun->localIP, &privIP);
    setTunPrivIP(privIP);

    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    if( (err = ioctl(sock, SIOCSIFADDR, &ifr)) < 0) 
    {
        ERROR_MSG("ioctl(SIOCSIFADDR) set IP failed");
        goto failure;
    }

    ifr.ifr_flags |= IFF_UP;
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    if( (err = ioctl(sock, SIOCSIFFLAGS, &ifr)) < 0) 
    {
        ERROR_MSG("ioctl(SIOCSIFFLAGS) set flags failed");
        goto failure;
    }
    
    // Set up SO_DONTROUTE for tunnel socket
    if(setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, tun->name, IFNAMSIZ) < 0)
    {
        ERROR_MSG("setsockopt(SO_DONTROUTE) on tunnel device failed");
        close(sock);
        return FAILURE;
    }

    close(sock);
    return fd;

failure:
    if(fd >= 0)
    {
        close(fd);
    }
    if(sock > 0)
    {
        close(sock);
    }

    return FAILURE;
} // End function int tunnelAlloc()


/*
 * T U N N E L  I N I T
 *
 * Function to initialize the tun device
 *
 * Returns (int):
 *      Success: tun device file descriptor
 *      Failure: -1
 *
 */
int tunnelInit()
{
#ifdef CONTROLLER
    char *privateIP = getTunnelIP();
    strncpy(tun->localIP, privateIP, IFNAMSIZ);
#endif

   int tunfd = -1;
   //tun = (struct tunnel *)malloc(sizeof(struct tunnel));

   if((tunfd = tunnelAlloc(tun)) < 0) 
   {
        ERROR_MSG("tunnelAlloc failed");
        return FAILURE;
   }

   if ( ioctl(tunfd, TUNSETNOCSUM, 1) < 0 )
   {
       ERROR_MSG("ioctl(TUNSETNOCSUM) failed");
       return FAILURE;
   } 


   // Port where proxy and gateway will listening at
   tun->remotePort 	    = WIROVER_PORT;
   tun->localPort       = WIROVER_PORT;
   setTunLocalPort(tun->localPort);

   if ( USE_CONTROLLER )
   {
      // Port where the control channel will be listening
      tun->controlPort 	= CONTROL_PORT;
   }

   return tunfd;
} // End function int tunnelInit(struct tunnel *tun)


/*
 * T U N N E L  C L E A N U P
 *
 * Function the cleanup the tunnel on successful exit
 *
 * Returns (void)
 *
 */
void tunnelCleanup()
{
    
    GENERAL_MSG("Cleaning up tunnel . . . \n");
    if ( tun->tunnelfd != 0 ) 
    {
        if ( close(tun->tunnelfd) < 0 )
        {
            DEBUG_MSG("close failed");
        }
    }

    if ( tun != NULL ) 
    {
        free(tun);
    }
} // End function void tunnelCleanup(struct tunnel *tun)


/*
 * T U N N E L  C R E A T E
 * 
 * A function to malloc, and initialize a tunnel structure
 *
 * Returns (struc tunnel)
 *      Success: a pointer to a tunnel structure
 *      Failure: NULL
 *
 */
struct tunnel *tunnelCreate()
{
    if( (tun = (struct tunnel *)malloc(sizeof(struct tunnel))) == NULL )
    {
        ERROR_MSG("malloc failed");
        return NULL;
    }
    
    memset(&tun->name, 0, sizeof(tun->name));
    memset(&tun->localIP, 0, sizeof(tun->localIP));

    tun->n_private_ip   = 0;
    tun->localPort      = 0;
    tun->remotePort     = 0;    
    tun->controlPort    = 0;

    tun->destAddr.sin_family        = 0;
    tun->destAddr.sin_port          = 0;  
    tun->destAddr.sin_addr.s_addr   = 0;

    tun->tunnelfd       = 0;

    return tun;
} // End function tunnelCreate()

/*
 * Returns the Unix standard time in microseconds modulo 2^32 and in network
 * byte order.  This has a valid range of about a day, which is plenty for
 * computing latency.
 *
 * If tv is null, gettimeofday is used instead.
 */
uint32_t getTunnelTimestamp(const struct timeval *tv)
{
    uint32_t tun_ts;
    if(tv) {
        tun_ts = tv->tv_sec * SEC_TO_USEC + tv->tv_usec;
    } else {
        struct timeval now;
        gettimeofday(&now, 0);

        tun_ts = now.tv_sec * SEC_TO_USEC + now.tv_usec;
    }

    // Avoid setting the timestamp to the special value.
    if(tun_ts == ntohl(TUNHDR_NO_TIMESTAMP)) {
        tun_ts++;
    }

    return htonl(tun_ts);
}

/*
 * Fills in the proper values for send_ts, recv_ts, and service in the
 * tunnel header.
 */
void fillTunnelTimestamps(struct tunhdr *tun_hdr, struct link *link)
{
    struct timeval now;
    gettimeofday(&now, 0);

    tun_hdr->send_ts = getTunnelTimestamp(&now);

    // Check just the seconds first to prevent overflow.
    if(link->last_tunhdr_send_ts != TUNHDR_NO_TIMESTAMP &&
            (now.tv_sec - link->last_arrival.tv_sec) < 
            LATENCY_MAX_INTER_DELAY) {
        unsigned delay = (now.tv_sec - link->last_arrival.tv_sec) * SEC_TO_USEC +
               (now.tv_usec - link->last_arrival.tv_usec);
        tun_hdr->recv_ts = link->last_tunhdr_send_ts;
        tun_hdr->service = htonl(delay);
        tun_hdr->prev_len = htons(link->last_pkt_len);
    } else {
        tun_hdr->recv_ts = TUNHDR_NO_TIMESTAMP;
        tun_hdr->service = TUNHDR_NO_TIMESTAMP;
        tun_hdr->prev_len = 0;
    }
}

/*
 * Computes the link latency based on the difference between the send time and
 * the arrival time.
 *
 * If arrival_time is null, gettimeofday is used instead.
 *
 * Returns TUNNEL_LATENCY_INVALID if unable to compute latency.
 */
unsigned computeTunnelLatency(const struct tunhdr *tun_hdr,
        const struct timeval *arrival_time)
{
    if(tun_hdr->recv_ts == TUNHDR_NO_TIMESTAMP ||
            tun_hdr->service == TUNHDR_NO_TIMESTAMP)
        return TUNNEL_LATENCY_INVALID;

    uint32_t curr_ts;
    if(arrival_time) {
        curr_ts = arrival_time->tv_sec * SEC_TO_USEC + arrival_time->tv_usec;
    } else {
        struct timeval now;
        gettimeofday(&now, 0);

        curr_ts = now.tv_sec * SEC_TO_USEC + now.tv_usec;
    }

    unsigned h_recv_ts = ntohl(tun_hdr->recv_ts);
    unsigned h_service = ntohl(tun_hdr->service);

    unsigned rtt = curr_ts - h_recv_ts;

    if(rtt < h_service)
        return TUNNEL_LATENCY_INVALID;

    return (rtt - h_service);
}

int finishTunnelMeasurement(struct tunnel_measurement *result,
        struct link *link, const struct tunhdr *tun_hdr, unsigned pkt_len, 
        const struct timeval *arrival_time)
{
    assert(result);

    if(tun_hdr->prev_len == 0)
        return 0;

    unsigned curr_ts;
    if(arrival_time) {
        curr_ts = arrival_time->tv_sec * SEC_TO_USEC + arrival_time->tv_usec;
    } else {
        struct timeval now;
        gettimeofday(&now, 0);
        curr_ts = now.tv_sec * SEC_TO_USEC + now.tv_usec;
    }

    const unsigned h_recv_ts = ntohl(tun_hdr->recv_ts);
    const unsigned h_service = ntohl(tun_hdr->service);

    // Length (in bits) of current two-way exchange
    const int curr_len = 8 * (ntohs(tun_hdr->prev_len) + pkt_len);

    int rtt = curr_ts - h_recv_ts;
    if(rtt >= h_service)
        rtt -= h_service;
    else
        return 0;

    int rtn = 0;
    if(link->prev_rtt > 0 && rtt != link->prev_rtt && 
            curr_len != link->prev_exchange_len) {
        // Bandwidth estimate (in bits / second)
        result->bandwidth = (float)(link->prev_exchange_len - curr_len) *
            (float)SEC_TO_USEC / (float)(link->prev_rtt - rtt);

        // Estimated one-way latency (in microseconds)
        result->latency = ((float)rtt - (8.0 * (float)SEC_TO_USEC * 
                    (float)pkt_len) / result->bandwidth) / 2.0;

        rtn = 1; //SUCCESS
    }
        
    link->prev_exchange_len = curr_len;
    link->prev_rtt = rtt;
    return rtn;
}

/*
 * Stores the timestamp information of a recently received packet in
 * the link structure so that the next outgoing packet on the same 
 * link can be filled with the appropriate timestamps.
 */
void updateTunnelTimestamps(struct link *link, const struct tunhdr *tun_hdr,
                unsigned pkt_len, const struct timeval *arrival_time)
{
    if(tun_hdr->send_ts != TUNHDR_NO_TIMESTAMP) {
        link->last_tunhdr_send_ts = tun_hdr->send_ts;
        link->last_pkt_len = pkt_len;
        memcpy(&link->last_arrival, arrival_time, sizeof(link->last_arrival));
    }
}


