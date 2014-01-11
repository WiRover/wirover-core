/* 
 * P C A P  S N I F F . C
 */

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "../common/tunnelInterface.h"
#include "../common/packet_debug.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/contChan.h"
#include "../common/udp_ping.h"
#include "../common/utils.h"
#include "../common/special.h"
#include "pcapSniff.h"

#define round(x) ((x)>=0?(int)((x)+0.5):(int)((x)-0.5))

static char local_buf[MAX_LINE];

static int              thread_running = 0;
static pthread_t        pcap_sniff_thread;
static pthread_mutex_t  pcap_sniff_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * P C A P  E V A L  S T R E A M
 *
 * The function that pcap_look will call
 *
 * Returns (void)
 */
void pcap_eval_stream(u_char *useless, const struct pcap_pkthdr *pcap_hdr, const u_char *packet)
{
    //struct ethhdr *eth_hdr = (struct ethhdr *)packet + 2;
    struct iphdr  *ip_hdr  = (struct iphdr *)(packet + 2 + sizeof(struct ethhdr));

    //print_iphdr(ip_hdr, NULL);

    // We want to filter out UDP Ping packets as that's what we will be using
    // for our BW estimation technique
    if ( ip_hdr->protocol == IPPROTO_UDP && (ip_hdr->daddr == inet_addr(getControllerIP())) )
    {
       // Pull out the UDP Header
       struct udphdr *udp_hdr = (struct udphdr *)(packet + 2 + sizeof(struct ethhdr) + sizeof(struct iphdr));
       //print_udphdr(udp_hdr, NULL);

       // If the destination port is UDP_PING_PORT then change the
       // ping_pkt_hdr we appended to the beginning of the packet
       if ( ntohs(udp_hdr->dest) == UDP_PING_PORT && ntohs(udp_hdr->source) == UDP_PING_PORT )
       {
           //print_udphdr(udp_hdr, NULL);
		   struct tunhdr* tun_hdr = (struct tunhdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));

           if (tun_hdr->seq_no == SPECIAL_PKT_SEQ_NO ) 
           {
               //printf("MODIFYING UDP PING PACKET (%ld) SEND TIME.\n", spl_hdr->local_seq_no);
               // Update the send_tv structure in the outgoing ping_pkt header that we've appended
               //gettimeofday(&spl_hdr->send_tv, NULL);
               //memcpy(&spl_hdr->send_tv, &pcap_hdr->ts, sizeof(struct timeval));
           }
       }
    }
} // End function void pcap_eval_stream(u_char *useless, const struct pcap_pkthdr *pcap_hdr, const u_char *packet)


/*
 * P C A P  S N I F F  T H R E A D  F U N C  
 *
 * Returns (void)
 *
 */
void *pcapSniffThreadFunc(void *arg)
{
    char *dev = (char *)arg;

    // The main thread should catch these signals.
    sigset_t new;
    sigemptyset(&new);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &new, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_t *desc;

    //dev = pcap_lookupdev(errbuf);       

    if ( dev == NULL ) 
    {
        sprintf(local_buf, "%s\n", errbuf);
        DEBUG_MSG(local_buf);
        return NULL;
    }

    desc = (struct pcap_t *)pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);

    if ( desc == NULL ) 
    {
        sprintf(local_buf, "%s", errbuf);
        DEBUG_MSG(local_buf);
        return NULL;
    }

    // If set to -1 will capture indefinitely
    int num_packets = -1;

    // pcap_dispatch will timeout, whereas pcap_loop won't
    //pcap_dispatch((pcap_t *)desc, num_packets, pcap_eval_stream, NULL);
    pcap_loop((pcap_t *)desc, num_packets, pcap_eval_stream, NULL);

    /*
    while ( ! getQuitFlag() ) 
    {
        struct interface *ife = getListHead();

        while( ife )
        {
            int avg_latency = sendUDPBurst(ife->name, getNodeID(), ife->link_id, ife->n_ip, inet_addr(getControllerIP()), NUM_BW_PKTS);
            if ( avg_latency > 0 )
            {
                // Split the latency in half and then change from milliseconds to seconds
                // to pass to calculateBandwidth()
                float time = (float)((float)(avg_latency / 2) / 1000);
                ife->stats.uplink_bw = calculateBandwidth((PACKET_SIZE * NUM_BW_PKTS), time);
            }

            sprintf(local_buf, "Device: (%s) uplink bw: %f (mbps)\n", ife->name, ife->stats.uplink_bw);
            STATS_MSG(local_buf);

            ife = ife->next;
        }

        sleep(10);
    }
    */

    pthread_exit(NULL);
} // void *pcapSniffThreadFunc(void *arg)


/*
 * C A L C U L A T E  W E I G H T S
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int calculateWeights()
{
    struct link *curr = head_link__; 
    double total_up_bw = 0;
    double total_dn_bw = 0;

    if( curr == NULL )
    {
        DEBUG_MSG("head_link__ is NULL in calculateWeights");
        return FAILURE;
    }

    // If there is only one interface on the system then default
    // the weights to 1
    if ( countLinks(head_link__) == 1 )
    {
        struct link *ife = head_link__;
        ife->up_weight = 1;
        ife->dn_weight = 1;
        return SUCCESS;
    }

	double smallest_up_bw = getLinkBandwidthUp(curr);
	double smallest_dn_bw = getLinkBandwidthDown(curr);

    while ( curr != NULL )
    {
        if ( curr->state != DEAD )
        {
            if ( getLinkBandwidthUp(curr) < smallest_up_bw || smallest_up_bw == 0 ) {
                smallest_up_bw = getLinkBandwidthUp(curr);
            }
                
            if ( getLinkBandwidthDown(curr) < smallest_dn_bw || smallest_dn_bw == 0 ) {
                smallest_dn_bw = getLinkBandwidthDown(curr);
            } 
        
            total_up_bw += getLinkBandwidthUp(curr);
            total_dn_bw += getLinkBandwidthDown(curr);
        }
        curr = curr->next;
    }

    double reciprocal_up = total_up_bw / smallest_up_bw;
    double reciprocal_dn = total_dn_bw / smallest_dn_bw;

    curr = head_link__;

    while ( curr != NULL )
    {
        if ( curr->state == ACTIVE )
        {
            
            curr->up_weight = (int)round(((getLinkBandwidthUp(curr)/total_up_bw)*reciprocal_up));
            curr->dn_weight = (int)round(((getLinkBandwidthDown(curr)/total_dn_bw)*reciprocal_dn));

            // Make sure none of the weights are 0
            if ( curr->up_weight == 0 )
            {
                curr->up_weight = 1;
            }
            if ( curr->dn_weight == 0 )
            {
                curr->dn_weight = 1;
            }
        }
        else
        {
            curr->up_weight = 1;
            curr->dn_weight = 1;
        }
        curr = curr->next;
    }

    //dumpInterfaces();
    return SUCCESS;
} // End function int calculateWeights()


/*
 * C R E A T E  P C A P  S N I F F  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int createPcapSniffThread()
{
    pthread_attr_t attr;

    if(thread_running) {
        return SUCCESS;
    }

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    struct link *ife = head_link__;
    while ( ife ) 
    {
        // TODO: This is creating multiple threads using a single pthread_t variable....
        if( pthread_create( &pcap_sniff_thread, &attr, pcapSniffThreadFunc, (void *)ife->ifname) )
        {
            ERROR_MSG("createPcapSniffThread(): pthread_create failed on pcapSniffThreadFunc");
            return FAILURE;
        }
        ife = ife->next;
    }

    thread_running = 1;

    pthread_attr_destroy(&attr);

    return SUCCESS;
} // End function createPcapSniffThread()


/*
 * D E S T R O Y  P C A P  S N I F F  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int destroyPcapSniffThread()
{ 
    if(!thread_running) {
        return SUCCESS;
    }

    GENERAL_MSG("Destroying pcap_sniff thread . . . ");
    if ( pthread_cancel(pcap_sniff_thread) != 0 )
    {
        ERROR_MSG("pthread_cancel(pcap_sniff_thread) failed");
        return FAILURE;
    }

    thread_running = 0;

    pthread_mutex_destroy(&pcap_sniff_mutex);

    return SUCCESS;
} // End function int destroyPcapSniffThread()


/*
 * I N C R E M E N T  B Y T E S  R E C V D 
 *
 * Returns (void)
 *  
 * Will be called by handleInboundPackets and will add packet counts to
 * each link.
 */
void incrementBytesRecvd(int link_id, int num_bytes)
{
    struct link *ife = searchLinksById(head_link__, link_id);
    if ( ife != NULL ) {
        ife->bytes_recvd += num_bytes;
    }
} // End function void incrementBytesRecvd()


/*
 * I N C R E M E N T  B Y T E S  S E N T
 *
 * Returns (void)
 *  
 * Will be called by handleInboundPackets and will add packet counts to
 * each link.
 */
void incrementBytesSent(int link_id, int num_bytes)
{
    struct link *ife = searchLinksById(head_link__, link_id);
    if ( ife != NULL ) {
        ife->bytes_sent += num_bytes;
    }
} // End function void incrementBytesRecvd()
