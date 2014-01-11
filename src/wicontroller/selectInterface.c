/* vim: set et ts=4 sw=4:
 *
 * S E L E C T  I N T E R F A C E . C
 *
 * This file contains that various algorithm code to select
 * an outgoing interface.
 *
 * Author: Joshua Hare hare@cs.wisc.edu
 *
 */
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "selectInterface.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/contChan.h"
#include "../common/utils.h"
#include "../common/special.h"
#include "../common/tunnelInterface.h"

const char* CONTROLLER_IFNAME = "CONT_PKT";

extern struct link *algoPerConnWrr(struct wigateway *list, const char *pkt, int len);

static char local_buf[MAX_LINE];

// Sequence number for outgoing packets to controller 
static unsigned out_seqNo = 0;

/*
 * I N I T  S E L E C T  I N T E R F A C E
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int initSelectInterface(int port)
{
    return SUCCESS;
} // End function initSelectInterface


/*
 *      G E T S E Q N O
 *
 * Returns (int): The next sequence number in network format
 *
 */
unsigned getSeqNo()
{
    unsigned temp = htonl(out_seqNo);
    out_seqNo++;
    if( out_seqNo == SPECIAL_PKT_SEQ_NO )
    {
        out_seqNo++;
    }

    return temp;
} // End function unsigned getSeqNo()


/*
 *
 * P E R _ C O N N _ R R
 *
 * Algorithm that will round robin interfaces per connection 
 * assumes this function will be called at the time hashing NAT info 
 *
 * Returns (unsigned )
 *      Success: a public IP address in network format
 *      Failure: -1
 *
 */
struct link* per_conn_rr(struct wigateway *gw_ptr, unsigned short port)
{
    //struct wigateway *gw_ptr = searchWigatewaysByIP(destIP);
    if( gw_ptr == NULL )
    {
        DEBUG_MSG("gw_ptr is NULL");
        return NULL;
    }

    struct link *ptr = gw_ptr->head_link;
    if( ptr == NULL )
    {
        DEBUG_MSG("no interfaces available");
        return NULL;
    }

    unsigned int loop = 0;
    int num_ifs = gw_ptr->num_interfaces;
    if ( num_ifs == 0 )
    {
        DEBUG_MSG("num_ifs is zero");
        return NULL;
    }

    int check = port % num_ifs;

    while(ptr) 
    {
        if(ptr->state == ACTIVE) 
        {
            if(loop == check) 
            {
                return ptr;
            }
            loop++;
        }
        ptr = ptr->next;
    }

    return NULL;
} // End function int per_conn_rr()

/*
 *
 *		P E R _ P A C K E T _ R R	
 *
 *  Algorithm that will round robin interfaces per packet
 *  assumes this function will be called for each packet
 *
 *  Returns
 *      Success: a public IP address in network format
 *      Failure: -1
 *
 */
struct link* per_packet_rr(struct wigateway *gw_ptr)
{
    //struct wigateway *gw_ptr = searchWigatewaysByIP(destIP);
    if( gw_ptr == NULL )
    {
        DEBUG_MSG("gw_ptr is NULL");
        return NULL;
    }

    int num_ifs = gw_ptr->num_interfaces;
    if( num_ifs == 0 ) 
    {
        DEBUG_MSG("num_ifs is zero");
        return NULL;
    }

    struct link *ptr = gw_ptr->head_link;
    if( ptr == NULL )
    {
        DEBUG_MSG("no available interfaces");
        return NULL;
    }

    unsigned int loop = 0;

    // ADDED BUF FIX
    gw_ptr->curr_RndRobin = (gw_ptr->curr_RndRobin + 1) % num_ifs;

    while(ptr) 
    {
        if(ptr->state == ACTIVE) 
        {
            if(loop == gw_ptr->curr_RndRobin) 
            {
                return ptr;
            }
            loop = (loop + 1) % num_ifs;
        }
        ptr = ptr->next;
    }

    DEBUG_MSG("per packet couldn't find anything to return");
    return NULL;
} // End function int per_packet_rr()


/*
 *
 *		P E R _ P A C K E T _ W R R	
 *
 *  Algorithm that will use weighted round robin interfaces per packet
 *  assumes this function will be called for each packet
 *
 */
struct link* per_packet_wrr(struct wigateway *gw_ptr)
{
    if( gw_ptr == NULL ) {
        DEBUG_MSG("gw_ptr is NULL");
        return NULL;
    }

    struct link *ptr = gw_ptr->head_link;

    int total_weight = 0;
    while(ptr) {
        if( ptr->state == ACTIVE ) {
            total_weight += ptr->dn_weight;
        }

        ptr = ptr->next;
    }

    if(total_weight == 0) {
        DEBUG_MSG("no available interfaces");
        return 0;
    }

    int index = 0;
    index = rand() % total_weight;

    int counter = 0;
    ptr = gw_ptr->head_link;
    while(ptr) {
        if(ptr->state == ACTIVE) {
            counter += ptr->dn_weight;
            if( counter > index ) {
                return ptr;
            }
        }

        ptr = ptr->next;
    }

    DEBUG_MSG("per packet couldn't find anything to return");
    return NULL;
} // End function int per_packet_wrr()


/*
 *
 *		P E R _ P A C K E T _ W R R _ v 1	
 *
 *  Algorithm that will use weighted round robin interfaces per packet
 *  assumes this function will be called for each packet
 *
 */
struct link* per_packet_wrr_v1(struct wigateway *gw_ptr)
{
    if( gw_ptr == NULL ) {
        DEBUG_MSG("gw_ptr is NULL");
        return NULL;
    }

    struct link *ptr = gw_ptr->head_link;

    int total_weight = 0;
    while(ptr) {
        if( ptr->state == ACTIVE ) {
            total_weight += ptr->dn_weight;
        }

        ptr = ptr->next;
    }

    if(total_weight == 0) {
        DEBUG_MSG("no available interfaces");
        return 0;
    }

    int index = 0;
    index = rand() % total_weight;

    int counter = 0;
    ptr = gw_ptr->head_link;
    while(ptr) {
        if(ptr->state == ACTIVE) {
            counter += ptr->dn_weight;
            if( counter > index ) {
                return ptr;
            }
        }

        ptr = ptr->next;
    }

    DEBUG_MSG("per packet couldn't find anything to return");
    return NULL;
} // End function int per_packet_wrr()

/* 
 * P E R _ P A C K E T _ S P F
 *
 * Per Packet Shortest Delay Path First
 *
 * Returns (int):
 *      Success: a pointer to the next valid interface
 *      Failure: -1
 */
struct link *per_packet_spf(struct wigateway *gw_ptr, int size)
{
    struct link *ptr = gw_ptr->head_link;

    struct link *spf_ptr = NULL;

    int packet_size = 1500;

    double min_delay = 9999999;

    double que_delay, link_delay, switching_delay;

    struct timeval now;


    while(ptr) {


    if( ptr->state == ACTIVE ) {
       gettimeofday(&now, 0);
       que_delay = ptr->que_delay - ((now.tv_sec - ptr->last_sent.tv_sec)*1000 +
               (now.tv_usec - ptr->last_sent.tv_usec)/1000) ;

        if (que_delay < 0 ) que_delay = 0;

switching_delay = (packet_size*8/(ptr->avg_active_bw_up))/1000 ;  // in msec

        double t_ul = ptr->avg_t_ul;  //Uplink Latency

        //if (t_ul < 0 ) t_ul = -t_ul;

        link_delay = que_delay + switching_delay + t_ul; //(ptr->avg_rtt)/2 ;

        sprintf(local_buf,"avg_uplink_latency: %f, est_delay: %f, que_delay: %f\n", t_ul, link_delay, que_delay);
        DEBUG_MSG(local_buf);

       if ((link_delay < min_delay) && (switching_delay < 9999999)) {
        spf_ptr = ptr;
        min_delay = link_delay;
        }

     }
    ptr = ptr->next;
    }

    if(min_delay == 9999999) {
        DEBUG_MSG("no available interfaces");
        return 0;
    }

    sprintf(local_buf,"Interface is: %s, est_delay: %f\n", spf_ptr->ifname, min_delay);
    DEBUG_MSG(local_buf);

    return spf_ptr;
} // End function int per_packet_spf()




/*
 *              N E W _ P E R _ P A C K E T _ W R R
 *
 *  The new weighted round robin algorithm
 *
 *  Returns (int):
 *      Success: a pointer to the next valid interface
 *      Failure: -1
 *
 */
struct link *curr_wrr = NULL;
int cur_weight = 0;
struct link* new_per_packet_wrr(struct wigateway *gw_ptr)
{
    if( gw_ptr == NULL ) {
        DEBUG_MSG("gw_ptr is NULL");
        return NULL;
    }

    unsigned int num_ifs = gw_ptr->num_interfaces;
    if( num_ifs == 0 ) {
        DEBUG_MSG("num_ifs is zero");
        return NULL;
    }

    struct link *ptr = gw_ptr->head_link;
    if( ptr == NULL ) {
        DEBUG_MSG("no available interfaces");
        return NULL;
    }

    //init the curr_wrr if needed
    if(curr_wrr == NULL) {
        curr_wrr = ptr;
    }

    ptr = curr_wrr;

    while( ptr != NULL )
    {
        printf("ptr: %p\n", ptr);
        if( (ptr->state == ACTIVE) && (ptr->curr_weight > 0) )
        {
            curr_wrr = ptr->next;
            ptr->curr_weight--;
            return ptr;
        }

        // Update the pointer
        if(ptr->next == NULL)
        {
            ptr = gw_ptr->head_link;
        }
        else
        {
            ptr = ptr->next;
        }

        if(ptr == curr_wrr)
        {
            break;
        }
    }

    // No interfaces were found so we need to reset curr_weights and reselect
    ptr = gw_ptr->head_link;
    curr_wrr = NULL;
    int check = 0;

    while(ptr)
    {
        if( (ptr->state == ACTIVE) && (check == 0) )
        {
            curr_wrr = ptr;
            ptr->curr_weight = ptr->dn_weight - 1;
            check = 1;
        }
        else
        {
            ptr->curr_weight = ptr->dn_weight;
        }
        ptr = ptr->next;
    }

    return curr_wrr;
} // End function int new_per_packet_wrr()


/*
 *
 *		P E R _ P A C K E T _ W D R R	
 *
 *  Algorithm that will use weighted deficit round robin interfaces per packet
 *  assumes this function will be called for each packet
 *
 */
/* weighted deficit round robin */
struct link *curr_wdrr = NULL;
struct link* per_packet_wdrr(struct wigateway *gw_ptr, int packet_size)
{
    int per_round_factor = 1400;

    int weight;
    if(curr_wdrr != NULL)
    {
        weight = curr_wdrr->dn_weight * per_round_factor;
    }

    if( (curr_wdrr != NULL) && (curr_wdrr->state == ACTIVE) )
    {
        if(packet_size < (weight + curr_wdrr->curr_weight) )
        {
            curr_wdrr->curr_weight += (weight - packet_size);
            return curr_wdrr;
        }
    }

    //struct wigateway *gw_ptr = searchWigatewaysByIP(destIP);

    if(gw_ptr == NULL)
    {
        DEBUG_MSG("gw_ptr is NULL");
        return NULL;
    }

    int num_ifs = gw_ptr->num_interfaces;

    if ( num_ifs == 0 ) 
    {
        DEBUG_MSG("num_ifs is zero");
        return NULL;
    }

    struct link *ptr = gw_ptr->head_link;
    unsigned int loop = 0;

    cur_weight = 0;
    gw_ptr->curr_RndRobin = (gw_ptr->curr_RndRobin + 1) % num_ifs;

    while(ptr) 
    {
        if(ptr->state == ACTIVE) 
        {
            if(loop == gw_ptr->curr_RndRobin) 
            {
                curr_wdrr = ptr;
                weight = curr_wdrr->dn_weight * per_round_factor;
                if(packet_size < (weight + curr_wdrr->curr_weight) )
                {
                    curr_wdrr->curr_weight += (weight - packet_size);
                    return curr_wdrr;
                }
            }
            loop = (loop + 1) % num_ifs;
        }
        ptr = ptr->next;
    }

    DEBUG_MSG("per packet couldn't find anything to return");
    return NULL;
} // End function int per_packet_wdrr()


/* 
 *
 * S E L E C T  I N T E R F A C E
 *
 * This functions is a wrapper that is globally visable to select the desired algorithm
 * and receive the socket file descriptor in return.  The algorithms are enumerated in
 * the header file.
 *
 */
int stripePacket(int fd, char *packet, int size, int offset)
{
    int algo = 0;
    unsigned short dport = 0;

    struct wigateway *gw_ptr = 0;

    const struct iphdr* ip_hdr = (const struct iphdr *)(packet + offset);
    if(ip_hdr->version == 4) {
        uint32_t ip = ip_hdr->daddr;
        gw_ptr = searchWigatewaysByIP(ip);

        // Get the destination port for RR_CONN.  This works for TCP too.
        const unsigned th_offset = offset + ip_hdr->ihl*4;
        if(size >= th_offset + 4) {
            const struct udphdr *udphdr = (const struct udphdr *)(packet + th_offset);
            dport = ntohs(udphdr->dest);
        }
    } else if(ip_hdr->version == 6) {
        // TODO: This makes the assumption that our IPv6 addresses include the
        // node id.  We may want a hash table mapping subnets to gateways
        // instead.
        const struct ip6_hdr* ip6_hdr = (const struct ip6_hdr *)ip_hdr;
        const uint16_t *ip = (const uint16_t *)ip6_hdr->ip6_dst.s6_addr;
        unsigned node_id = (ntohs(ip[3]) & 0xfff0) >> 4;
        gw_ptr = searchWigatewaysByNodeID(node_id);
    } else {
        DEBUG_MSG("Unrecognized ip version field (%u)", ip_hdr->version);
        return FAILURE;
    }

    if(!gw_ptr) {
        DEBUG_MSG("Gateway unrecognized, not connected");
        return FAILURE;
    }

    // Debug
    //dumpNetworkTunHdr(&tun_hdr);

    // Copy in the algorithm that the gw is using
    algo = gw_ptr->algo;

    struct link* sel_link = 0;
    switch(algo) 
    {
        case RR_CONN:
            sel_link = per_conn_rr(gw_ptr, dport);
            break;

        case RR_PKT:
            sel_link = per_packet_rr(gw_ptr);
            break;

        case WRR_CONN:
            sel_link = algoPerConnWrr(gw_ptr, packet + offset, size - offset);
            break;

        case WRR_PKT:
            sel_link = per_packet_wrr(gw_ptr);
            break;
        
        case WRR_PKT_v1:
            sel_link = per_packet_wrr_v1(gw_ptr);
            break;

        case SPF:
            sel_link = per_packet_spf(gw_ptr, size);
            break;
        
        case WDRR_PKT:
            sel_link = per_packet_wdrr(gw_ptr, size);
            break;

        default:
            return FAILURE;
    }

    if(sel_link == NULL) {
        ERROR_MSG("selectInterface returned zero\n");
        return FAILURE;
    }

    struct tunhdr tun_hdr;
    memset(&tun_hdr, 0, sizeof(struct tunhdr));

    // Construct tunnel header for outgoing packet
    tun_hdr.seq_no = getSeqNo();
    tun_hdr.client_id = 0; // TODO: Can we use this?
    tun_hdr.node_id = htons(gw_ptr->node_id);
    tun_hdr.link_id = htons(sel_link->id);
    tun_hdr.local_seq_no = htons(sel_link->local_seq_no_out++);

    fillTunnelTimestamps(&tun_hdr, sel_link);

    // Assemble the outgoing packet
    char *tunnel_packet = (char *)malloc(size + sizeof(struct tunhdr) - offset);
    memcpy(tunnel_packet, &tun_hdr, sizeof(struct tunhdr));
    memcpy(&tunnel_packet[sizeof(struct tunhdr)], &packet[offset], (size-offset));

    int new_size = (size - offset) + sizeof(struct tunhdr);

    // Copy the dest IP into the myDest structure
    // TODO: This is not IPv6 compatible; use getaddrinfo() instead.
    uint32_t n_ip = getLinkIpv4(sel_link);
    if(n_ip == 0) {
        DEBUG_MSG("getLinkIpv4 failed");
        free(tunnel_packet);
        return FAILURE;
    }

    struct sockaddr_in  myDest;
    memset(&myDest, 0, sizeof(myDest));
    myDest.sin_family       = AF_INET;
    myDest.sin_addr.s_addr  = n_ip;
    myDest.sin_port         = sel_link->data_port;

    // Send packets back to the gateway
    int rtn = sendto(fd, tunnel_packet, new_size, 0, (struct sockaddr *)&myDest, sizeof(myDest));

    // Do not forget to free the memory!
    free(tunnel_packet);
    tunnel_packet = 0;

    if( rtn < 0)
    {
        ERROR_MSG("sendto() failed");
        return FAILURE;
    }
    else
    {
        gw_ptr->num_bytes_sent_to += rtn;

        // Bytes received from the gateway's point of view
        incLinkBytesRecvd(sel_link, rtn);

        snprintf(local_buf, sizeof(local_buf), "Bytes sent to node %d: %llu, to link %d (%s): %llu",
                gw_ptr->node_id, gw_ptr->num_bytes_sent_to, sel_link->id, sel_link->ifname, sel_link->bytes_recvd);
        STATS_MSG(local_buf); 
    }

    return rtn;
} // End function int stripePacket()

