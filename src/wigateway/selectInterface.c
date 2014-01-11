/*
 *  
 * S E L E C T  I N T E R F A C E . C
 *
 * This file contains that various algorithm code to select
 * an outgoing interface.
 *
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/tunnelInterface.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/contChan.h"
#include "../common/utils.h"
#include "../common/packet_debug.h"
#include "../common/sockets.h"
#include "pcapSniff.h"
#include "transfer.h"
#include "selectInterface.h"

extern struct link *algoPerConnWrr(struct link *list, const char *pkt, int len);

static char local_buf[MAX_LINE];
static unsigned int cur_RndRobin;
static struct sockaddr_in myDest;

// Sequence number for outgoing packets to controller 
static uint32_t out_seqNo = 0;
static struct link *curr_wdrr = NULL;
static struct link *curr_wrr = NULL;
static int cur_weight = 0;
int coded_packets=0;
/*
 * I N I T  S E L E C T  I N T E R F A C E
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int initSelectInterface(struct tunnel *tun)
{
    memset(&myDest, 0, sizeof(myDest));
    myDest.sin_family = PF_INET;
    myDest.sin_port   = htons((unsigned short)tun->remotePort);
    inet_pton(AF_INET, tun->remoteIP, &myDest.sin_addr);
    memset(code_buffer, 0, MTU);

    return SUCCESS;
} // End function int initSelectInterface()


/*
 * G E T  S E Q  N O
 *
 * Returns: The next sequence number
 *
 */
uint32_t getSeqNo()
{
     uint32_t temp = htonl(out_seqNo);
     out_seqNo++;
     if ( out_seqNo == 0xFFFFFFFF ) 
     {
         out_seqNo++;
     }

     return temp;
} // End function uint32_t getSeqNo()


/*
 *
 * P E R _ C O N N _ R R
 *
 * Algorithm that will round robin interfaces per connection 
 * assumes this function will be called at the time hashing NAT info 
 *
 * Returns (int):
 *      Success: a pointer to the next interface
 *      Failure: -1
 *
 */
struct link *per_conn_rr(struct link *list, unsigned short port)
{
    struct link *ptr = NULL;
    unsigned int loop = 0;
    unsigned int num_ifs = countActiveLinks(list);

    if ( num_ifs == 0 )
    {
        DEBUG_MSG("getNumActiveInterfaces() returned 0");
        return NULL;
    }

    int check = port % num_ifs;

    ptr = list;

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
 * packet is expected to start at the IPv{4,6} header.
 */
struct link *per_conn_wrr(struct link *list, char *packet, int len)
{
    return algoPerConnWrr(list, packet, len);
}

/*
 *
 * P E R _ P A C K E T _ R R	
 *
 * Algorithm that will round robin interfaces per packet
 * assumes this function will be called for each packet
 *
 * Returns (int):
 *      Success: A pointer to the next valid interface
 *      Failure: -1
 *
 */
struct link *per_packet_rr(struct link *list)
{
    unsigned int num_ifs = countActiveLinks(list);

    if ( num_ifs == 0 ) 
    {
        return NULL;
    }

    struct link *ptr = NULL;
    unsigned int loop = 0;

    ptr = list;

    // ADDED BUF FIX
    cur_RndRobin = (cur_RndRobin + 1) % num_ifs;

    while(ptr) 
    {
        if(ptr->state == ACTIVE) 
        {
            if(loop == cur_RndRobin) 
            {
                return ptr;
            }
            loop = (loop + 1) % num_ifs;
        }
        ptr = ptr->next;
    }

    return NULL;
} // End function int per_packet_rr()


/* 
 * P E R _ P A C K E T _ W R R
 *
 * Weighted Round Robin algorithm
 *
 * Returns (int):
 *      Success: a pointer to the next valid interface
 *      Failure: -1
 */
#if 0
struct interface *per_packet_wrr_old(struct interface *list)
{
    unsigned int num_ifs = getNumActiveInterfaces();

    if ( num_ifs == 0 ) 
    {
        return NULL;
    }

    int weight;

    if(curr_wrr != NULL)
    {
        weight = curr_wrr->up_weight;
    }

    if( (cur_weight < (weight-1)) && (curr_wrr != NULL) && (curr_wrr->state == ACTIVE) )
    {
        cur_weight++;
        return curr_wrr;
    }

    struct interface *ptr = NULL;
    unsigned int loop = 0;

    ptr = list;

    cur_weight = 0;
    cur_RndRobin = (cur_RndRobin + 1) % num_ifs;

    while(ptr) 
    {
        if(ptr->state == ACTIVE) 
        {
            if(loop == cur_RndRobin) 
            {
                curr_wrr = ptr;
                return ptr;
            }
            loop = (loop + 1) % num_ifs;
        }
        ptr = ptr->next;
    }

	return NULL;
} // End function int per_packet_wrr()
#endif

struct link *per_packet_wrr(struct link *list)
{
    struct link *ptr = list;

    //add up the weights for active interfaces
    int total_weight = 0;
    while(ptr) {
        if( ptr->state == ACTIVE ) {
            total_weight += ptr->up_weight;
        }

        ptr = ptr->next;
    }

    if(total_weight == 0) {
        DEBUG_MSG("no available interfaces");
        return 0;
    }

    //generate a random number
    int index = 0;
    //srand( time(NULL) );
    index = rand() % total_weight;
    //printf("index is: %d total_weight is: %d\n", index, total_weight);

    //loop through and find the interface
    int counter = 0;
    ptr = list;
    while(ptr)
    {
        if( ptr->state == ACTIVE )
        {
            counter += ptr->up_weight;
            if( counter > index )
            {
                return ptr;
            }
        }
        ptr = ptr->next;
    }

    DEBUG_MSG("error: random count larger than total link weights");
    return NULL;
} // End function int per_packet_wrr()


/* 
 * P E R _ P A C K E T _ W R R _ v 1
 *
 * Weighted Round Robin algorithm with delay constraint
 *
 * Returns (int):
 *      Success: a pointer to the next valid interface
 *      Failure: -1
 */
struct link *per_packet_wrr_v1(struct link *list)
{
    struct link *ptr = list;

    //add up the weights for active interfaces
    int total_weight = 0;
    while(ptr) {
   sprintf(local_buf,"link up_bw is: %d avg_rtt is: %f\n", ptr->up_weight, ptr->avg_rtt);
   DEBUG_MSG(local_buf);

        if( ptr->state == ACTIVE && ptr->avg_rtt < RTT_ACCEPTABLE) {
            total_weight += ptr->up_weight;
        }

        ptr = ptr->next;
    }

    if(total_weight == 0) {
        DEBUG_MSG("no available interfaces");
        return 0;
    }

    //generate a random number
    int index = 0;
    //srand( time(NULL) );
    index = rand() % total_weight;
    sprintf(local_buf,"index is: %d total_weight is: %d\n", index, total_weight);
    DEBUG_MSG(local_buf);    

    //loop through and find the interface
    int counter = 0;
    ptr = list;
    while(ptr)
    {
        if( ptr->state == ACTIVE && ptr->avg_rtt < RTT_ACCEPTABLE)
        {
            counter += ptr->up_weight;
            if( counter > index )
            {
                return ptr;
            }
        }
        ptr = ptr->next;
    }

    DEBUG_MSG("error: random count larger than total link weights");
    return NULL;
} // End function int per_packet_wrr_v1()


/* 
 * P E R _ P A C K E T _ S P F
 *
 * Per Packet Shortest Delay Path First
 *
 * Returns (int):
 *      Success: a pointer to the next valid interface
 *      Failure: -1
 */
struct link *per_packet_spf(struct link *list, int size)
{
    struct link *ptr = list;

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
 * N E W _ P E R _ P A C K E T _ W R R
 *
 * The new weighted round robin algorithm
 *
 * Returns (int):
 *      Success: a pointer to the next valid interface
 *      Failure: -1
 *
 */
struct link *new_per_packet_wrr(struct link *list)
{
    unsigned int num_ifs = countActiveLinks(list);

    if ( num_ifs == 0 ) 
    {
        return NULL;
    }

    struct link *ptr = NULL;

    if(curr_wrr == NULL)
    {
        curr_wrr = list;
    }

    ptr = curr_wrr;

    while(ptr) 
    {
        if( (ptr->state == ACTIVE) && (ptr->stats.curr_weight > 0) ) 
        {
            curr_wrr = ptr->next;
            ptr->stats.curr_weight--;
            return ptr;
        }

        // Update the pointer
        if(ptr->next == NULL)
        {
            ptr = list;
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
    ptr = list;
    curr_wrr = NULL;
    int check = 0;

    while(ptr)
    {
        if( (ptr->state == ACTIVE) && (check == 0) )
        {
            curr_wrr = ptr;
            ptr->stats.curr_weight = ptr->up_weight - 1;
            check = 1;
        }
        else
        {
            ptr->stats.curr_weight = ptr->up_weight;
        }
        ptr = ptr->next;
    }

	return curr_wrr;
} // End function int new_per_packet_wrr()


/* 
 * P E R _ P A C K E T _ W D R R
 *
 * Weighted Deficit Round Robin algorithm
 *
 * Returns (int):
 *      Success: address of next valid interface
 *      Failure: -1 
 *
 */
struct link *per_packet_wdrr(struct link *list, int packet_size)
{
    int per_round_factor = 400;
    unsigned int num_ifs = countActiveLinks(list);

    if ( num_ifs == 0 ) 
    {
        return NULL;
    }

    int weight;

    if(curr_wrr != NULL)
    {
        weight = curr_wdrr->up_weight * per_round_factor;
    }

    if( (curr_wdrr != NULL) && (curr_wdrr->state == ACTIVE) )
    {
        if( packet_size < (weight + curr_wdrr->stats.curr_weight) )
        {
            curr_wdrr->stats.curr_weight += (weight - packet_size);
            return curr_wdrr;
        }
    }

    struct link *ptr = NULL;
    unsigned int loop = 0;

    ptr = list;

    cur_weight = 0;
    cur_RndRobin = (cur_RndRobin + 1) % num_ifs;

    while(ptr) 
    {
        if(ptr->state == ACTIVE) 
        {
            if(loop == cur_RndRobin) 
            {
                curr_wdrr = ptr;
                weight = curr_wdrr->up_weight * per_round_factor;
                if( packet_size < (weight + curr_wdrr->stats.curr_weight) )
                {
                    curr_wdrr->stats.curr_weight += weight - packet_size;
                    return ptr;
                }
            }
            loop = (loop + 1) % num_ifs;
        }
        ptr = ptr->next;
    }

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
 * Returns (int):
 *     Success: address of next valid interface
 *      Failure: -1 
 *
 */
struct link *selectInterface(int algo, unsigned short port, int size)
{
    struct link *head = head_link__;

    switch(algo)
    {
        case RR_CONN:
        return per_conn_rr(head, port);

        case RR_PKT:
        return per_packet_rr(head);

        case WRR_CONN:
        //return per_conn_wrr(head, port);

        case WRR_PKT:
        return per_packet_wrr(head);

        case WRR_PKT_v1:
        return per_packet_wrr_v1(head);

        case WDRR_PKT:
        return per_packet_wdrr(head, size);
        
        case SPF:
        return per_packet_spf(head, size);

        default:
        return NULL;
    }
    
    DEBUG_MSG("Algo not found");

    return NULL;
} // End function int selectInterface()


/*
 * S T R I P E  P A C K E T
 *
 * Send a packet out depending on the algorithm being used.
 *
 * Returns (int)
 *      Success: the number of bytes sent out
 *      Failure: -1
 *
 */
int stripePacket(char *packet, int size, int algo)
{
    int rtn = 0;
    struct link *head = head_link__;
    struct link *ife = NULL;
        
    int offset = 0;
    if( USE_CONTROLLER )
        offset = TUNTAP_OFFSET;
    else
        offset = ETH_HLEN;

    unsigned short port = 0;
    if(algo == RR_CONN)
    {
        int th_offset;
        int proto = find_transport_header(packet + offset, size - offset, &th_offset);
        if(proto == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + offset + th_offset);
            port = ntohs(tcp_hdr->source);
        } else if(proto == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr *)(packet + offset + th_offset);
            port = ntohs(udp_hdr->source);
        } else if(proto < 0) {
            // The packet was invalid, so drop it.
            return FAILURE;
        }
    }

    switch(algo) 
    {
        case RR_CONN:
            ife = per_conn_rr(head, port);
            break;

        case RR_PKT:
            ife = per_packet_rr(head);
            break;

        case WRR_CONN:
            ife = per_conn_wrr(head, packet + offset, size - offset);
            break;

        case WRR_PKT:
            ife = per_packet_wrr(head);
            break;

        case WRR_PKT_v1:
            ife = per_packet_wrr_v1(head);
        
        case WDRR_PKT:
            ife = per_packet_wdrr(head, size);
            break;

        case SPF:
            ife = per_packet_spf(head, size);
            break;
        
        default:
            return FAILURE;
    }

    if ( ife == NULL )
    {
        ERROR_MSG("stripe algorithm returned NULL");
        return FAILURE;
    }

    if( USE_CONTROLLER )
    {
        // Getting a sequence number should be done as close to sending as possible
        struct tunhdr tun_hdr;
        uint16_t codeLen=CODELEN;
        memset(&tun_hdr, 0, sizeof(tun_hdr));

        tun_hdr.seq_no = htonl(getSeqNo());
        tun_hdr.client_id = 0; // TODO: Add a client ID.
        tun_hdr.node_id = htons(getNodeID());
        tun_hdr.link_id = htons(ife->id);
	tun_hdr.local_seq_no = htons(ife->local_seq_no_out++);
        
        fillTunnelTimestamps(&tun_hdr, ife);

        DEBUG_MSG("SeqNo is %d link_id is %d", tun_hdr.seq_no, tun_hdr.link_id);
        //memcpy(packet, &pktSeqNo, sizeof(pktSeqNo));
        char *new_packet = (char *)malloc(size + sizeof(struct tunhdr) - TUNTAP_OFFSET);
        memcpy(new_packet, &tun_hdr, sizeof(struct tunhdr));
        memcpy(&new_packet[sizeof(struct tunhdr)], &packet[TUNTAP_OFFSET], (size-TUNTAP_OFFSET));
        int new_size = (size-TUNTAP_OFFSET) + sizeof(struct tunhdr);

#if 0
        if( EVDO_BUFFERING )
        {
            if( (rtn = mySendto(ife->sockfd, new_packet, new_size, 0, (struct sockaddr *)&myDest, sizeof(struct sockaddr), ife)) < 0)
            {
                ERROR_MSG("mySendto failed");
            }
            else
            {
                ife->stats.bytes_sent += rtn;
            }

            pthread_mutex_lock(&ife->condition_mutex);
            pthread_cond_signal(&ife->condition_cond);
            pthread_mutex_unlock(&ife->condition_mutex);
        }
        else
#endif


            //sprintf(local_buf, "Sending out ife->name: %s, %d", ife->name, ife->sockfd);
            //DEBUG_MSG(local_buf);
            //printf("tun_hdr.seq_no: %d, tun_hdr.ifname: %s\n", tun_hdr.seq_no, tun_hdr.ifname);
            //printIp(myDest.sin_addr.s_addr);
            //printf("myDest.sin_port: %hd\n", ntohs(myDest.sin_port));
            
            if( (rtn = sendto(ife->sockfd, new_packet, new_size, 0, (struct sockaddr *)&myDest, sizeof(struct sockaddr))) < 0)
            {
                sprintf(local_buf, "sendto failed (%d), socket: %d, new_size: %d", rtn, ife->sockfd, new_size);
                ERROR_MSG(local_buf);
            }
            else
            {
               ife->stats.bytes_sent += rtn;
               
               struct timeval now;
               gettimeofday(&now, 0); 
               
               
               double que_delay = ife->que_delay - ((now.tv_sec - ife->last_sent.tv_sec)*1000 +  (now.tv_usec - ife->last_sent.tv_usec)/1000) ;

               if (que_delay < 0 ) que_delay = 0;
       
               que_delay = que_delay + (rtn*8/(ife->avg_active_bw_up))/1000 ;

               ife->que_delay = que_delay;

               gettimeofday(&ife->last_sent,0);
            }
        
 #ifdef NETWORK_CODING
        xorPackets(new_packet, new_size);
        coded_packets++;
     
     if (coded_packets == codeLen){
        coded_packets = 0;
        //ife = best_ife;
        tun_hdr.seq_no = htonl(getSeqNo());
        tun_hdr.client_id = codeLen; // TODO: Add a client ID.
        tun_hdr.node_id = htons(getNodeID());
        tun_hdr.link_id = htons(ife->id);
        tun_hdr.local_seq_no = htons(ife->local_seq_no_out++);

        fillTunnelTimestamps(&tun_hdr, ife);

        //memcpy(packet, &pktSeqNo, sizeof(pktSeqNo));
        char *coded_packet = (char *)malloc(MTU + sizeof(struct tunhdr));
        memcpy(coded_packet, &tun_hdr, sizeof(struct tunhdr));
        memcpy(&coded_packet[sizeof(struct tunhdr)], code_buffer, MTU);
        int new_size = (MTU+ sizeof(struct tunhdr));

                
        rtn = sendto(ife->sockfd, coded_packet, new_size, 0, (struct sockaddr *)&myDest, sizeof(struct sockaddr));
        DEBUG_MSG("Sent coded packet:%d bytes",rtn);
        free(coded_packet);
        
    memset(code_buffer, 0, MTU);
       }
 #endif
        free(new_packet);
    }
    else
    {
        // FIXME: The code below may not work and definitely does not support IPv6.

        unsigned short old_sum, new_sum;
        unsigned short eth_type = htons(0x0800);
        uint32_t old_ip, new_ip;
        char header[ETH_HLEN];
        unsigned char routers_addr[ETH_ALEN] = {0x00, 0x00, 0x0c, 0x07, 0xac, 0x00};

        struct iphdr  *ip_hdr;
        struct udphdr *udp_hdr;
        struct tcphdr *tcp_hdr;

        // Fill in the ethernet header
        memcpy(&header[0], routers_addr, ETH_ALEN);
        memcpy(&header[ETH_ALEN], &ife->hwaddr, ETH_ALEN);
        memcpy(&header[ETH_ALEN*2], &eth_type, 2);

        // FIll the source IP and checksum
        memcpy(packet, header, ETH_HLEN);

		new_ip = getLinkIpv4(ife);
		if(new_ip == 0) {
			DEBUG_MSG("Failed getting link's IP address");
		}

        ip_hdr = (struct iphdr *)&packet[ETH_HLEN];
        memcpy(&old_ip, &ip_hdr->saddr, sizeof(old_ip));
        memcpy(&old_sum, &ip_hdr->check, sizeof(old_sum));

        // IP checksum
        new_sum = htons(updateCsum(ntohl(new_ip), ntohl(old_ip), ntohs(old_sum)));
        memcpy(&ip_hdr->saddr, &new_ip, sizeof(ip_hdr->saddr));
        memcpy(&ip_hdr->check, &new_sum, sizeof(unsigned short));
        
        //print_iphdr(ip_hdr, NULL);

        if(ip_hdr->protocol == IPPROTO_UDP)
        {
            udp_hdr = (struct udphdr *)(packet + ETH_HLEN + ip_hdr->ihl*4);
            memcpy(&old_sum, &udp_hdr->check, sizeof(unsigned short));
            new_sum = htons(updateCsum(ntohl(new_ip), ntohl(old_ip), ntohs(old_sum)));
            memcpy(&udp_hdr->check, &new_sum, sizeof(unsigned short));
        }
        else if(ip_hdr->protocol == IPPROTO_TCP)
        {
            tcp_hdr = (struct tcphdr *)(packet + ETH_HLEN + ip_hdr->ihl*4);
            memcpy(&old_sum, &tcp_hdr->check, sizeof(unsigned short));
            new_sum = htons(updateCsum(ntohl(new_ip), ntohl(old_ip), ntohs(old_sum)));
            memcpy(&tcp_hdr->check, &new_sum, sizeof(unsigned short));
        }

        if( ife->stats.flags & IFF_POINTOPOINT )
        {
#if 0
            // Hack for ppp0 -> doesn't use an ethernet header, thus copy from that point
            if( EVDO_BUFFERING )
            {
                if( (rtn = myWrite(ife->sockfd, &packet[ETH_HLEN], (size-ETH_HLEN), ife)) < 0)
                {
                    ERROR_MSG("myWrite failed");
                }
                else 
                {
                    ife->stats.bytes_sent += rtn;
                }

                pthread_mutex_lock(&ife->condition_mutex);
                pthread_cond_signal(&ife->condition_cond);
                pthread_mutex_unlock(&ife->condition_mutex);
            }
            else
#endif
            {
                if( (rtn = write(ife->sockfd, &packet[ETH_HLEN], (size-ETH_HLEN))) < 0)
                {
                    ERROR_MSG("write failed");
                }
                else 
                {
                    ife->stats.bytes_sent += rtn;
                }
            }
        }
        else
        {
            // Otherwise copy as normally
            if( (rtn = write(ife->sockfd, packet, (size+ETH_HLEN))) < 0)
            {
                ERROR_MSG("write failed");
            }
            else 
            {
                //printf("Wrote %d bytes\n", rtn);
                ife->stats.bytes_sent += rtn;
            }
        }
    }

    incrementBytesSent(ife->id, rtn);

    return rtn;
} // End function int stripePacket()


int xorPackets(char *buf, int len){
 int i;

 len = MIN(len, MTU);
 
 for (i=0; i<len; i++){
 code_buffer[i] = (code_buffer[i]) ^ (buf[i]);
 }

return len;

}
