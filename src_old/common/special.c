/* vim: set expandtab: */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "parameters.h"
#include "../common/debug.h"
#include "interface.h"
#include "link.h"
#include "tunnelInterface.h"
#include "contChan.h"
#include "special.h"
#include "utils.h"
#include "../common/handleTransfer.h"
#include "udp_ping.h"

#ifdef GATEWAY
#include "../wigateway/gpsHandler.h"
#endif

#ifdef CONTROLLER
#include "../wicontroller/gatewayUpdater.h"
#endif

/* ---------------- Receiving functions -------------------- */


int handleNatPunch(char *buf, const struct sockaddr *from, socklen_t fromlen);
int handleUDPPingCont(int sockfd, char *packet, struct sockaddr *from, struct timeval *kernel_delay);
int handleUDPPingGw(int sockfd, char *packet, struct sockaddr *from, struct timeval *kernel_delay);

#ifdef CONTROLLER
/* 
 * H A N D L E  N A T  P U N C H
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int handleNatPunch(char *buf, const struct sockaddr *from, socklen_t fromlen)
{
    // At this point we know this is a special NAT PUNCH packet
    //printf("received a nat punch packet from: %s\n", inet_ntoa(from->sin_addr));


    int              h_private_ip;
    short            h_state;
    unsigned short   h_link_id;
    struct wigateway *gateway;

    struct nat_punch_pkt punch_pkt;
    memcpy(&punch_pkt, buf, sizeof(struct nat_punch_pkt));

    // Extract the information in host byte order
    h_private_ip = ntohl(punch_pkt.priv_ip);
    h_state = ntohs(punch_pkt.state);
    h_link_id = ntohs(punch_pkt.link_id);
            
    char p_ip[INET6_ADDRSTRLEN];
    char port_str[16];
    getnameinfo(from, fromlen, p_ip, sizeof(p_ip), port_str, sizeof(port_str), 
            NI_NUMERICHOST | NI_NUMERICSERV);
    
    /* Grab the source port of the nat punch.  If the gateway is behind a nat,
     * we need to know what destination port to use for the return traffic. */
    unsigned short n_data_port = ntohs((unsigned short)atoi(port_str));
    
    if ( (gateway = (struct wigateway *)searchWigatewaysByID(punch_pkt.hw_addr)) != NULL )
    {
        time(&gateway->last_seen_pkt_time);

        struct link* link = searchLinksById(gateway->head_link, h_link_id);
        if(link) {
            // The network name may have changed.
            strncpy(link->network, punch_pkt.network, sizeof(link->network));
            
            STATS_MSG("Received nat punch from node %u link %d (%s / %s) from %s:%s",
                    gateway->node_id, link->id, link->ifname, 
                    link->network, p_ip, port_str);

            // Update the link state
            link->state = h_state;

            link->data_port = n_data_port;

#ifdef WITH_MYSQL
            // Update link status in database
            gw_update_link(gateway, link);
#endif
        } else {
            // We received a nat punch, but we do not recognize the link.  We
            // should add it and begin using it.
            DEBUG_MSG("Adding missing link %d (%s / %s) to node %u",
                    h_link_id, punch_pkt.device, punch_pkt.network, gateway->node_id);
            
            addGwLink(gateway, (char*)punch_pkt.device, p_ip, n_data_port, 
                    punch_pkt.network, h_state, 1, h_link_id, 1);
            dumpWigateways();
        }
    }
    else
    {
        DEBUG_MSG("Notification received, but gateway ID unrecognized");

        // If the gateway's IP is available, we can restore its old lease;
        // otherwise, its only hope is to restart the gateway software.
        if( leaseAvailable(h_private_ip, 0) ) {
            DEBUG_MSG("Gateway is using a valid IP, restoring its lease");

            gateway = createGateway();

            memcpy(gateway->id, punch_pkt.hw_addr, ETH_ALEN);
            gateway->node_id = computeNodeId(gateway->id, ETH_ALEN);

            //TODO: Fix the DMZ port!
            restoreLease(gateway, punch_pkt.priv_ip, 9000);

            // Update the gateway's information in the database
            changeGwState(gateway, GW_STATE_ACTIVE);

            // Add the only link we know about at the moment
            addGwLink(gateway, (char*)punch_pkt.device, p_ip, n_data_port,
                    punch_pkt.network, ACTIVE, 1, h_link_id, 1);

            dumpWigateways();

        } else {
            DEBUG_MSG("Would restore lease but IP is invalid or unavailable");
        }

    }

    return SUCCESS;
} // End function int handleNatPunch()
#endif


/*
 * B U R S T  B U F  I S  F U L L
 */
int burstBufIsFull(struct ping_pkt *burst_buf[])
{
    int i = 0;
    for ( i = 0 ; i < NUM_PINGS ; i++ )
    {
        struct tunhdr* tun_hdr = (struct tunhdr*)burst_buf[i];

        if ( tun_hdr->seq_no == BURST_FILTER ) 
        {
            return 0; 
        }
    }

    return 1;
} // End function int burstBufIsFull()



#ifdef GATEWAY
/*
 * H A N D L E  U D P  P I N G  G W 
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
/*
int handleUDPPingGw(int sockfd, char *packet, struct sockaddr *from, struct timeval *kernel_rcv_time) 
{
    struct ping_pkt *udp_ping = (struct ping_pkt *)packet;

    udp_ping->recv_tv.tv_sec = kernel_rcv_time->tv_sec;
    udp_ping->recv_tv.tv_usec = kernel_rcv_time->tv_usec;

    int hash_val = udp_ping->local_seq_no;

    if ( hash_val > NUM_PINGS ) 
    {
        DEBUG_MSG("Ping Packet local sequence number is greater than expected.\n");
        return FAILURE;
    }
    
    struct interface *ife = interfaceLookupByLinkID(udp_ping->tun_hdr.link_id);

    if ( ife != NULL )
    {
        // Copy the packet into the local burst buffer
        memcpy(ife->burst_buf[hash_val], udp_ping, sizeof(struct ping_pkt));
    }

    // Check if the buffer is full, if so then run the packetPair algorithm
    if ( burstBufIsFull(ife->burst_buf) ) 
    {
        packetPairGw(udp_ping->tun_hdr.ifname);
    }

    return SUCCESS;
} // End function int handleUDPPingGw(int rcv_sockfd)
*/
#endif


#ifdef CONTROLLER
/*
 * H A N D L E  U D P  P I N G  C O N T
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
/*
int handleUDPPingCont(int sockfd, char *packet, struct sockaddr *from, struct timeval *kernel_rcv_time) 
{
    struct ping_pkt *udp_ping = (struct ping_pkt *)packet;

    udp_ping->recv_tv.tv_sec = kernel_rcv_time->tv_sec;
    udp_ping->recv_tv.tv_usec = kernel_rcv_time->tv_usec;

    struct wigateway *gw = (struct wigateway *)searchWigatewaysByNodeID(udp_ping->tun_hdr.node_id);
    int link_is_valid = 0;

    if ( gw != NULL ) 
    {
        struct gw_link *link = (struct gw_link *)gw->head_ip_entry;
        while ( link )
        {
            if ( link->link_id == udp_ping->tun_hdr.link_id)
            {
                link_is_valid = 1;
                break;
            }
            link = link->next;
        }
    }

    if ( gw != NULL && link_is_valid )
    {
        //printf("kernel_delay.tv_sec: %d\tkernel_delay.tv_usec: %d\n", (int)kernel_delay->tv_sec, (int)kernel_delay->tv_usec);
        //printf("result.tv_sec: %d\tresult.tv_usec: %d\n", (int)result.tv_sec, (int)result.tv_usec);

    int hash_val = (udp_ping->local_seq_no % NUM_PINGS);

        struct gw_link *curr = gw->head_ip_entry;
        while ( curr )
        {
            // If this is the matching link, then copy in the udp ping
            if ( curr->link_id == udp_ping->tun_hdr.link_id ) 
            {
                //Only print GPS for the first ping packet
                if(hash_val == 0) {
                    //Update gateway GPS data so that it can be put into the database
                    gw->gps_status = udp_ping->gps_status;
                    gw->latitude = udp_ping->latitude;
                    gw->longitude = udp_ping->longitude;
                    gw->altitude = udp_ping->altitude;

                    gw_update_status(gateways_database, gw);

                    sprintf(local_buf, "GPS from node %d status %d lat %f long %f alt %f", gw->node_id, udp_ping->gps_status, udp_ping->latitude, udp_ping->longitude, udp_ping->altitude);
                    STATS_MSG(local_buf)
                }

                //printf("RECEIVED PING BURST FROM GW node id: %d, link_id: %d, hash_val: %d\n", gw->node_id, curr->link_id, hash_val);
                // TODO: JOSH: could copy the GW's IP address here so that NAT's are not an issue
                curr->n_public_ip = ((struct sockaddr_in *)from)->sin_addr.s_addr;
                inet_ntop(PF_INET, &((struct sockaddr_in *)from)->sin_addr.s_addr, curr->p_public_ip, MAX_IP_ASCII);
                //printf("received a ping packet from: %s\n", inet_ntoa(((struct sockaddr_in *)from)->sin_addr));

                memcpy(curr->burst_buf[hash_val], udp_ping, sizeof(struct ping_pkt));
                break;
            }

            curr = curr->next;
        }

        // If the buffer is full, then echo back the burst of UDP pings
        if ( burstBufIsFull(curr->burst_buf) ) 
        {
            packetPairCont(curr, udp_ping->tun_hdr.ifname);

            // Echo the ping burst back (buffered so as to remove the artificial buffer created
            // by the uplink bandwidth
            int i = 0;
            for (i = 0 ; i < NUM_PINGS ; i++ )
            {
                struct ping_pkt *pkt = (struct ping_pkt *)curr->burst_buf[i]; 

                // Put the uplink bandwidth we calculated in the echo packet
                pkt->tun_hdr.link_id = curr->link_id;
                pkt->uplink_bw = curr->bw;

                if ( pkt->tun_hdr.seq_no != BURST_FILTER ) 
                {
                    if( sendto(sockfd, pkt, sizeof(struct ping_pkt), 0, (struct sockaddr *)from, sizeof(struct sockaddr)) < 0)
                    {
                        DEBUG_MSG("handleUDPPingCont() failed to send ping reply");
                        return FAILURE;
                    }
                    pkt->tun_hdr.seq_no = BURST_FILTER;
                }
            }
            //printf("ECHO'd Burst Back to link_id: %d\n", curr->link_id);
        }
    }
    else
    {
        // We don't recognize this gateway, but it may just be coming up, so just
        // echo ping packets straight back to it
        if( sendto(sockfd, packet, sizeof(struct ping_pkt), 0, (struct sockaddr *)from, sizeof(struct sockaddr)) < 0)
        {
            DEBUG_MSG("handleUDPPingCont() failed to send ping reply");
            return FAILURE;
        }
    }

    return SUCCESS;
} // End function int handleUDPPingCont(int rcv_sockfd)
*/
#endif


#ifdef GATEWAY
/*
 * P A C K E T  P A I R  G W
 */
/*
void packetPairGw(char *dev_name)
{
    struct interface *ife = (struct interface *)interfaceLookup(dev_name);

    // Packet pair algorithm
    // http://www.hpl.hp.com/personal/Kevin_Lai/projects/nettimer/publications/usits2001/node2.html
                
    // Total bits transferred will be the number of pings times the size of each packet
    // times eight bits per byte
    int total_bits = (NUM_PINGS * PING_SIZE * 8); 

    struct timeval send_diff, recv_diff, rel_diff, adj_rel_diff;
    struct timeval artificial_delay;

    // We introduce 5000 microseconds delay on the send side
    artificial_delay.tv_sec = 0;
    artificial_delay.tv_usec = 0;
     
    struct ping_pkt *head = (struct ping_pkt *)ife->burst_buf[0];
    struct ping_pkt *tail = (struct ping_pkt *)ife->burst_buf[NUM_PINGS-1];

    // Make sure the packets showed up 'in order'
    if ( tail->local_seq_no == (head->local_seq_no + NUM_PINGS - 1) )
    {
        //printf("tail->send_tv.tv_sec: %d\thead->send_tv.tv_sec: %d\n", tail->send_tv.tv_sec, head->send_tv.tv_sec);
        //printf("tail->send_tv.tv_usec: %d\thead->send_tv.tv_usec: %d\n", tail->send_tv.tv_usec, head->send_tv.tv_usec);
        //printf("tail->recv_tv.tv_sec: %d\thead->recv_tv.tv_sec: %d\n", tail->recv_tv.tv_sec, head->recv_tv.tv_sec);
        //printf("tail->recv_tv.tv_usec: %d\thead->recv_tv.tv_usec: %d\n", tail->recv_tv.tv_usec, head->recv_tv.tv_usec);

        // Make sure we don't get negative numbers 
        // (may happen since clock skews are off/preemption of packets)
        if ( (tail->send_tv.tv_sec >= head->send_tv.tv_sec && tail->send_tv.tv_usec >= head->send_tv.tv_usec) &&
                (tail->recv_tv.tv_sec >= head->recv_tv.tv_sec && tail->recv_tv.tv_usec >= head->recv_tv.tv_usec) )
        {
            timersub(&tail->send_tv, &head->send_tv, &send_diff);
            timersub(&tail->recv_tv, &head->recv_tv, &recv_diff);

            // Make sure the differences aren't negative
            if ( recv_diff.tv_sec >= send_diff.tv_sec && recv_diff.tv_usec >= send_diff.tv_usec )
            {
                timersub(&recv_diff, &send_diff, &rel_diff);
                //printf("send_diff.tv_sec: %d, send_diff.tv_usec: %d\n", send_diff.tv_sec, send_diff.tv_usec);
                //printf("recv_diff.tv_sec: %d, recv_diff.tv_usec: %d\n", recv_diff.tv_sec, recv_diff.tv_usec);
                //printf("rel_diff.tv_sec: %d, rel_diff.tv_usec: %d\n", rel_diff.tv_sec, rel_diff.tv_usec);

                // Subtract off the artificially introduced delay
                timersub(&rel_diff, &artificial_delay, &adj_rel_diff);
                //printf("adj_rel_diff.tv_sec: %d, adj_rel_diff.tv_usec: %d\n", adj_rel_diff.tv_sec, adj_rel_diff.tv_usec);

                // Calculate the relative delay between a pair of packets being sent from
                // the gateway to the controller, normalize the result
                double rel_delay = (double)adj_rel_diff.tv_sec + (double)((double)adj_rel_diff.tv_usec / 1000000);

                if ( rel_delay > 0 ) 
                {
                    // Update the devices bandwidth estimates
                    if ( ife != NULL ) 
                    {
                        // The new_bw is the bw we just calculated from the estimations above
                        float new_downlink_bw = ((double)total_bits / rel_delay);

                        //printf("\nPacket pair estimation (%s downlink): %f (mbps)\n", ife->name, new_downlink_bw / 1000000);
                        ife->stats.downlink_total_bw += new_downlink_bw;
                        ife->stats.downlink_bw_avg       = (float)((double)ife->stats.downlink_total_bw / (double)ife->stats.downlink_avg_count);
                        if ( ife->stats.downlink_bw > 0 )
                        {
                            ife->stats.downlink_bw_weighted  = (float)( ALPHA * ife->stats.downlink_bw ) + (float)( BETA * new_downlink_bw);
                        }
                        ife->stats.downlink_bw = new_downlink_bw;

                        // Since we have a burst size of N, then we have N estimations
                        // of the uplink bandwidth from the controller, take the average
                        // of those estimates and use that as our estimated uplink bw number
                        int i = 0;
                        float burst_uplink_total_bw  = 0;
                        float burst_uplink_avg_count = 0;
                        for ( i = 0 ; i < NUM_PINGS ; i++ )
                        {
                            burst_uplink_total_bw += ife->burst_buf[i]->uplink_bw;    
                            burst_uplink_avg_count++; 
                        }
                        float new_uplink_bw = (float)((double)burst_uplink_total_bw / (double)burst_uplink_avg_count);

                        //printf("Packet pair estimation (%s uplink): %f (mbps)\n", ife->name, new_uplink_bw / 1000000);
                        // Sum in the total bw
                        for ( i = 0 ; i < NUM_PINGS ; i++ )
                        {
                            ife->stats.uplink_total_bw += ife->burst_buf[i]->uplink_bw;    
                            ife->stats.uplink_avg_count++; 
                        }

                        ife->stats.uplink_bw_avg       = (float)((double)ife->stats.uplink_total_bw / (double)ife->stats.uplink_avg_count);
                        if ( ife->stats.uplink_bw > 0 ) 
                        {
                            ife->stats.uplink_bw_weighted  = (float)( ALPHA * ife->stats.uplink_bw ) + (float)( BETA * new_uplink_bw);
                        }
                        ife->stats.uplink_bw = new_uplink_bw;

                        sprintf(local_buf, "ABET_PP (%s):", dev_name);
                        STATS_MSG(local_buf);

                        if ( ife->stats.downlink_bw != 0 ) 
                        {
                            sprintf(local_buf, "downlink bw: %f (mbps), average: %f (mbps), weighted: %f (mbps)",
                                (ife->stats.downlink_bw / 1000000), 
                                (ife->stats.downlink_bw_avg / 1000000), 
                                (ife->stats.downlink_bw_weighted / 1000000));
                            STATS_MSG(local_buf);
                        }

                        if ( ife->stats.uplink_bw != 0 )
                        {
                            sprintf(local_buf, "uplink bw: %f (mbps), average: %f (mbps), weighted: %f (mbps)\n", 
                                (ife->stats.uplink_bw / 1000000), 
                                (ife->stats.uplink_bw_avg / 1000000), 
                                (ife->stats.uplink_bw_weighted / 1000000));
                            STATS_MSG(local_buf);
                        }


                        ife->stats.downlink_avg_count++;
                    }
                }
            }
        }
    }
} // End function void packetPairGw()
*/
#endif


/*
 * P A C K E T  P A I R  C O N T
 */
/*
void packetPairCont(struct gw_link *link, char *dev_name)
{
    // Packet pair algorithm
    // http://www.hpl.hp.com/personal/Kevin_Lai/projects/nettimer/publications/usits2001/node2.html
                
    // Total bits transferred will be the number of pings times the size of each packet
    // times eight bits per byte
    int total_bits = (NUM_PINGS * PING_SIZE * 8); 

    struct timeval send_diff, recv_diff, rel_diff, adj_rel_diff;
    struct timeval artificial_delay;

    // We introduce 5000 microseconds delay on the send side
    artificial_delay.tv_sec = 0;
    artificial_delay.tv_usec = 0;
     
    struct ping_pkt *head = (struct ping_pkt *)link->burst_buf[0];
    struct ping_pkt *tail = (struct ping_pkt *)link->burst_buf[NUM_PINGS-1];

    // Make sure the packets showed up 'in order'
    if ( tail->local_seq_no == (head->local_seq_no + NUM_PINGS - 1) )
    {
        //printf("tail->send_tv.tv_sec: %d\thead->send_tv.tv_sec: %d\n", tail->send_tv.tv_sec, head->send_tv.tv_sec);
        //printf("tail->send_tv.tv_usec: %d\thead->send_tv.tv_usec: %d\n", tail->send_tv.tv_usec, head->send_tv.tv_usec);
        //printf("tail->recv_tv.tv_sec: %d\thead->recv_tv.tv_sec: %d\n", tail->recv_tv.tv_sec, head->recv_tv.tv_sec);
        //printf("tail->recv_tv.tv_usec: %d\thead->recv_tv.tv_usec: %d\n", tail->recv_tv.tv_usec, head->recv_tv.tv_usec);

        // Make sure we don't get negative numbers 
        // (may happen since clock skews are off/preemption of packets)
        if ( (tail->send_tv.tv_sec >= head->send_tv.tv_sec && tail->send_tv.tv_usec >= head->send_tv.tv_usec) &&
                (tail->recv_tv.tv_sec >= head->recv_tv.tv_sec && tail->recv_tv.tv_usec >= head->recv_tv.tv_usec) )
        {
            timersub(&tail->send_tv, &head->send_tv, &send_diff);
            timersub(&tail->recv_tv, &head->recv_tv, &recv_diff);

            // Make sure the differences aren't negative
            if ( recv_diff.tv_sec >= send_diff.tv_sec && recv_diff.tv_usec >= send_diff.tv_usec )
            {
                timersub(&recv_diff, &send_diff, &rel_diff);
                //printf("send_diff.tv_sec: %d, send_diff.tv_usec: %d\n", send_diff.tv_sec, send_diff.tv_usec);
                //printf("recv_diff.tv_sec: %d, recv_diff.tv_usec: %d\n", recv_diff.tv_sec, recv_diff.tv_usec);
                //printf("rel_diff.tv_sec: %d, rel_diff.tv_usec: %d\n", rel_diff.tv_sec, rel_diff.tv_usec);

                // Subtract off the artificially introduced delay
                timersub(&rel_diff, &artificial_delay, &adj_rel_diff);
                //printf("adj_rel_diff.tv_sec: %d, adj_rel_diff.tv_usec: %d\n", adj_rel_diff.tv_sec, adj_rel_diff.tv_usec);

                // Calculate the relative delay between a pair of packets being sent from
                // the gateway to the controller, normalize the result
                double rel_delay = (double)adj_rel_diff.tv_sec + (double)((double)adj_rel_diff.tv_usec / 1000000);

                if ( rel_delay > 0 ) 
                {
                    // The new_bw is the bw we just calculated from the estimations above
                    link->new_bw = ((double)total_bits / rel_delay);

                    // Add the new_bw to the total so we can find an average
                    link->total_bw += link->new_bw;

                    // Calculate the average bandwidth
                    link->avg_bw = (float)((double)link->total_bw / (double)link->avg_count);

                    if ( link->avg_count == 1 )
                    {
                        link->bw = link->new_bw;
                    }
                    else
                    {
                        link->bw = link->weighted_bw;
                    }

                    // Weighted bw is ALPHA * bw + BETA * new_bw
                    link->weighted_bw = (float)( ALPHA * link->bw ) + (float)( BETA * link->new_bw);
                    link->avg_count++;
                }
            }
        }
    }
} // End function void packetPairCont()
*/

/* ---------------- Sending functions -------------------- */


// Function prototype
void *sendBurstFunc(void *); 
void *sendPingFunc(void *); 

struct ping_params {
    char device[IFNAMSIZ];
    short node_id;
    short link_id;
    int sockfd;
    int burstLen;
    int spacing;

    uint32_t remoteIP;
    uint32_t localIP;
    int pingPort;
};

struct ping_params pingParams;
struct sockaddr_in pingServer;

#ifdef GATEWAY
/*
 * N A T  P U N C H
 * 
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int natPunch(struct link *ife, uint32_t dAddr, uint16_t dPort, uint16_t sPort)
{
    int retval = FAILURE;

    //GENERAL_MSG("Punching holes in NAT . . .");
    //printf("Punching holes in NAT . . . interface: %s\n", ife->name);
    struct sockaddr_in bindAddr;
    struct sockaddr_in sendAddr;
    struct ifreq ifr;
    int sockfd = 0;
    int rtn = 0;
    int tunPrivIP = getTunPrivIP();

    const unsigned packet_size = sizeof(struct udphdr) + sizeof(struct nat_punch_pkt);
    char packet[packet_size];
    int curr_packet_index = 0;

    // Get a socket handle
    if( (sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0 ) {
        ERROR_MSG("natPunch(): creating socket failed");
        return FAILURE;
    }

    memset(&bindAddr, 0, sizeof(struct sockaddr_in));
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_port        = htons(sPort);
    bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    // Bind socket to port
    if(bind(sockfd, (struct sockaddr *)&bindAddr, sizeof(struct sockaddr_in)) < 0)
    {
        DEBUG_MSG("natPunch(): bind socket");
        goto close_and_return;
    }

    // Bind socket to device
    memset(&ifr, 0, sizeof(struct ifreq));
    if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ife->ifname, IFNAMSIZ) < 0)
    {
        DEBUG_MSG("natPunch(): SO_BINDTODEVICE failed");
        goto close_and_return;
    }

    /*
    // Bind socket to device
    char on = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        DEBUG_MSG("natPunch(): IP_HDRINCL failed");
        close(sockfd);
        return FAILURE;
    }
    */

    memset(&sendAddr, 0, sizeof(struct sockaddr_in));
    sendAddr.sin_family       = AF_INET;
    sendAddr.sin_port         = htons(dPort);
    sendAddr.sin_addr.s_addr  = dAddr;

/*
    // Build the IP header
    struct iphdr ip_hdr;
    memset(&ip_hdr, 0, sizeof(struct iphdr));
    ip_hdr.version      = 4;
    ip_hdr.ihl          = sizeof(struct iphdr) / 4;
    ip_hdr.tos          = 0;
    ip_hdr.tot_len      = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + packet_size);
    ip_hdr.id           = 0x0000;
    ip_hdr.frag_off     = 0;
    ip_hdr.ttl          = MAXTTL;
    ip_hdr.protocol     = IPPROTO_UDP;
    ip_hdr.check        = 0;
    ip_hdr.saddr        = ife->n_ip;
    ip_hdr.daddr        = htonl(dAddr);
    //ip_hdr.check        = csum(&ip_hdr, ip_hdr.ihl);
*/

    // Build the UDP header
    struct udphdr udp_hdr;
    memset(&udp_hdr, 0, sizeof(struct udphdr));
    udp_hdr.source = htons(WIROVER_PORT);
    udp_hdr.dest   = htons(WIROVER_PORT);
    udp_hdr.len    = htons(packet_size);
    udp_hdr.check  = 0x0000;

    struct nat_punch_pkt punch_pkt;
    memset(&punch_pkt, 0, sizeof(struct nat_punch_pkt));
    punch_pkt.seq_no = SPECIAL_PKT_SEQ_NO;
    punch_pkt.type = htons(SPKT_NAT_PUNCH);
    memcpy(punch_pkt.hw_addr, getUniqueID(), ETH_ALEN);
    punch_pkt.priv_ip = tunPrivIP;
    punch_pkt.algo = htons((short)getRoutingAlgorithm());
    strncpy(punch_pkt.device, ife->ifname, sizeof(punch_pkt.device));
    readNetworkName(ife->ifname, ife->network, sizeof(ife->network));
    strncpy(punch_pkt.network, ife->network, sizeof(punch_pkt.network));

    punch_pkt.pub_ip = getLinkIpv4(ife);
    if(punch_pkt.pub_ip == 0) {
        DEBUG_MSG("Failed to get link's IP address");
        goto close_and_return;
    }

    punch_pkt.state = htons(ife->state);
    punch_pkt.src_port = htons(sPort);
    punch_pkt.weight = htons(ife->dn_weight);
    punch_pkt.link_id = ntohs(ife->id);
    
    memcpy(&packet[curr_packet_index], &udp_hdr, sizeof(struct udphdr));
    curr_packet_index+=sizeof(struct udphdr);

    memcpy(&packet[curr_packet_index], &punch_pkt, sizeof(struct nat_punch_pkt));
    curr_packet_index+=sizeof(struct nat_punch_pkt);

    // TODO: Get rid of hack
    // Add a special route to the controller just to set up communication
    /*if ( ife != NULL )
    {
        if ( ife->has_gw )
        {
            addGWRoute(getControllerIP(), "255.255.255.255", ife->gw_ip, ife->name);
        }
        else
        {
            addRoute(getControllerIP(), "255.255.255.255", ife->name);
        }
    }*/

    if( (rtn = sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&sendAddr, sizeof(struct sockaddr))) < 0)
    {
        ERROR_MSG("natPunch(): sendto failed");
        goto close_and_return;
    }
    //printf("sent packet on socket: %d to source: %d from dest: %d rtn=%d\n", sockfd, sPort, dPort, rtn);

    //delRoute(getControllerIP(), "255.255.255.255", ife->name);

    retval = SUCCESS;

close_and_return:
    close(sockfd);
    return retval;
} // End function int natPunch()
#endif
