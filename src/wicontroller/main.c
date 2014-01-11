/* vim: set et ts=4 sw=4:
 *  
 * M A I N . C
 *
 * This file manages the packet encapsulation/tunneling to the 
 * WiRover controller. It keeps a list of currently available
 * outgoing interfaces and opens a tun/tap device to the local
 * system that is used to interface with an iptables NAT.
 *
 * The tunnel encapsulates the packets with IP/UDP headers for
 * a specific port on the controller that receives the gateway's
 * packets.
 *
 * Traffic coming from the controller is decapsulated and written
 * to the tun/tap device which in turn will deliver the packet
 * to the iptables NAT to deNAT the packet and forward to the 
 * clients.
 *
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>

#include "gatewayUpdater.h"
#include "selectInterface.h"

#include "../common/active_bw.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/contChan.h"
#include "../common/link.h"
#include "../common/reOrderPackets.h"
#include "../common/udp_ping.h"
#include "../common/utils.h"
#include "../common/tunnelInterface.h"
#include "../common/packet_debug.h"
#include "../common/passive_bw.h"
#include "../common/special.h"


static sigset_t      orig_set, block_set;
static unsigned char dmz_source_mac[ETH_ALEN];

static char               internal_if[CONFIG_FILE_PARAM_DATA_LENGTH];
static char               local_buf[MAX_LINE];
static unsigned long long total_bytes_recvd = 0;



int handleNatPunch(char *buf, const struct sockaddr *from, socklen_t fromlen);
void updatePacketLoss(struct link* link, unsigned short curr_seq_no);

/*
 * O P E N  R A W  S O C K
 *
 * Returns (int): 
 *      Success: a socket file descriptor
 *      Failure: -1
 *
 */
int openRawsock(char *device, int protocol)
{
    int rawsock;

    if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol))) < 0)
    {
        ERROR_MSG("raw socket failed");
        close(rawsock);
        return FAILURE;
    }

    struct sockaddr_ll sll;
    struct ifreq ifr;

    bzero(&sll, sizeof(sll));
    bzero(&ifr, sizeof(ifr));

    // First Get the Interface Index  
    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
    if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
    {
        ERROR_MSG("ioctl(SIOGIFINDEX) failed");
        return FAILURE;
    }

    // Bind our raw socket to this interface
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);

    if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
    {
        ERROR_MSG("bind failed");
        return FAILURE;
    }

    return rawsock;
} // End function openRawsock()


/*
 * F O R W A R D  P A C K E T
 * 
 * Forward a packet to the specified internal device (i.e. buswatch)
 *
 * Returns (int)
 *  Success: 0
 *  Failure: -1
 j
 */
int forwardPacket(int fwd_sockfd, int sockfd)
{
    // Look for TCP or UDP and port numbers, do a lookup
    // in a table and determine which gateway to send to
    // Find out what gateway we need to send to based on the
    // port number and then put that IP into the header

    char buf[MTU]; 
    int offset, bufSize;
    struct wigateway *gw = NULL;
    struct ethhdr   *eth_hdr;
    struct iphdr    *ip_hdr;
    struct tcphdr   *tcp_hdr;

    struct sockaddr_in from;
    int fromlen = sizeof(struct sockaddr_in);

    if( (bufSize = recvfrom(fwd_sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen)) < 0) 
    {
        ERROR_MSG("recvfrom() sockfd failed");
        return FAILURE;
    } 

    offset = sizeof( struct ethhdr );

    ip_hdr = (struct iphdr *)(buf + offset); 

    // We know they're using TCP for the buswatch traffic
    if ( ip_hdr->protocol == IPPROTO_TCP )
    {
        tcp_hdr = (struct tcphdr *)(buf + offset + ip_hdr->ihl*4);
        //if ( ntohs(tcp_hdr->dest) != 22 ) { printf("port: %d\n", ntohs(tcp_hdr->dest)); }
        if ( (gw = searchWigatewaysByPort(ntohs(tcp_hdr->dest))) == NULL )
        {
            goto DROP_PACKET;
        }
        else
        {
            //printf("found gw\n");
        }
    }
    else
    {
        goto DROP_PACKET;
    }

    if ( gw == NULL ) 
    {
        goto DROP_PACKET;
    }
    else
    {
        eth_hdr = (struct ethhdr *)(buf);
        //print_ethhdr(eth_hdr, NULL);

        // Store off the incoming MAC address in the ethernet header so that
        // We can copy back in on the way out (raw sockets)
        memcpy(dmz_source_mac, eth_hdr->h_source, sizeof(eth_hdr->h_source));
        //printf("Saving off %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n\n",
        //    dmz_source_mac[0], dmz_source_mac[1], dmz_source_mac[2], dmz_source_mac[3], dmz_source_mac[4], dmz_source_mac[5]);

        // Update checksum of the TCP header
        tcp_hdr->check = htons(updateCsum(ntohl(gw->n_private_ip), ntohl(ip_hdr->daddr), ntohs(tcp_hdr->check)));

        // Update checksum of IP header
        ip_hdr->check = htons(updateCsum(ntohl(gw->n_private_ip), ntohl(ip_hdr->daddr), ntohs(ip_hdr->check)));

        // Copy over the IP address that we want to send to
        memcpy(&ip_hdr->daddr, &gw->n_private_ip, sizeof(gw->n_private_ip));

        sprintf(local_buf, "Forwarding traffic to: %s %hd\n", gw->p_private_ip, ntohs(tcp_hdr->dest));
        STATS_MSG(local_buf);
        GENERAL_MSG(local_buf);
        
        // Ethernet header needs to be truncated to mimic tun packet.  Providing additional 4 bytes
        // for sequence number.
        offset = TUNTAP_OFFSET;
        stripePacket(sockfd, buf+sizeof(struct ethhdr)-TUNTAP_OFFSET, bufSize-sizeof(struct ethhdr)+TUNTAP_OFFSET, offset);
    }

DROP_PACKET:
    return SUCCESS;
} // End function int forwardPacket()


/*
 * H A N D L E  O U T B O U N D  P A C K E T
 * 
 * This function handles packets coming from a WiGateway
 * and going out to the internet
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int handleOutboundPacket(int sockfd, int tunfd)
{
    uint32_t  pktSeqNo;
    unsigned short codeLen, linkID; 

    int  bufSize;
    char buf[MTU];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);

    struct tunhdr   *tun_hdr;

    // Receive the packet from the gateways and then forward it out to the internets
    bufSize = recvfrom(sockfd, buf, sizeof(buf), 0, 
            (struct sockaddr *)&from, &fromlen);
    if(bufSize < 0) {
        ERROR_MSG("recvfrom() sockfd failed");
        return FAILURE;
    } else if(bufSize < sizeof(struct tunhdr)) {
        // Packet is too small to be an encapsulated packet; silently ignore it.
        return SUCCESS;
    }

    struct timeval arrival_time;
    if(ioctl(sockfd, SIOCGSTAMP, &arrival_time) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&arrival_time, 0);
    }

    tun_hdr = (struct tunhdr *)buf;

    // This gets the sequence number from the packet
    memcpy(&pktSeqNo, &tun_hdr->seq_no, sizeof(tun_hdr->seq_no));

    
   if ( pktSeqNo == NAT_PUNCH_SEQ_NO )
    {
        if ( handleNatPunch(buf, (struct sockaddr *)&from, fromlen) < 0 )
        {
            return FAILURE;
        }

        return SUCCESS;
    }


    // This gets the code length, link ID from the packet
    linkID = ntohs(tun_hdr->link_id);
    codeLen = ntohs(tun_hdr->client_id);

    DEBUG_MSG("Rcvd SeqNo: %d LinkID: %d codeLen: %d",pktSeqNo, linkID, codeLen);

    /*
    else
    {
        sprintf(local_buf, "Seq No: %d sent at %ld.%06ld.", pktSeqNo, sent->tv_sec, sent->tv_usec);
        STATS_MSG(local_buf);

        gettimeofday(arrived, &tz);
        timersub(arrived, sent, result);

        sprintf(local_buf, "Seq No: %d arrived at %ld.%06ld.", pktSeqNo, arrived->tv_sec, arrived->tv_usec);
        STATS_MSG(local_buf);

        sprintf(local_buf, "Seq No: %d took %ld.%06ld seconds to get to get to the controller.", pktSeqNo, result->tv_sec, result->tv_usec);
        STATS_MSG(local_buf);
    }

    free(sent);
    free(arrived);
    free(result);
    */

    total_bytes_recvd += bufSize;
    sprintf(local_buf, "Bytes recvd (from all wigateways): %llu", total_bytes_recvd);
    STATS_MSG(local_buf);

    unsigned short h_node_id = ntohs(tun_hdr->node_id);
    struct wigateway *gw = searchWigatewaysByNodeID(h_node_id);
    if(gw) {
        gw->num_bytes_recvd_from += bufSize;
        time(&gw->last_seen_pkt_time);
        
        unsigned short h_link_id = ntohs(tun_hdr->link_id);

        struct link* link;
        link = searchLinksById(gw->head_link, h_link_id);
        if(link) {
            time(&link->last_packet_received);
            link->packets++;

            // Store it as bytes sent from the gateway's point of view
            incLinkBytesSent(link, bufSize);
        
            // Check for lost or out-of-order packets
            unsigned short localSeqNo = ntohs(tun_hdr->local_seq_no);
            updatePacketLoss(link, localSeqNo);
            sprintf(local_buf, "Bytes recvd from node %d: %llu, from link %d (%s): %llu",
                    gw->node_id, gw->num_bytes_recvd_from, h_link_id, link->ifname, link->bytes_sent);
            STATS_MSG(local_buf);

            if(link->state != ACTIVE) {
                DEBUG_MSG("Packet from node %d link %d (%s) on INACTIVE link, setting to ACTIVE",
                        gw->node_id, h_link_id, link->ifname);
                link->state = ACTIVE;
                gw_update_link(gw, link);
            }


#ifdef USE_PASSIVE_RTT
            struct tunnel_measurement tmeas;
            if(finishTunnelMeasurement(&tmeas, link, tun_hdr, bufSize,
                        &arrival_time)) {
                STATS_MSG("Tunnel measurement for node %u link %u (%s): "
                        "latency %f, bandwidth %f (age %u)",
                        h_node_id, h_link_id, link->network, 
                        tmeas.latency, tmeas.bandwidth, ntohl(tun_hdr->service));
            }

            updateTunnelTimestamps(link, tun_hdr, bufSize, &arrival_time);
#endif
        }
    }

    // This is needed to notify tun0 we are passing an IP packet
    // Have to pass in the IP proto as last two bytes in ethernet header
    //
    // Copy in four bytes, these four bytes represent the four bytes of the
    // tunnel header (added by the tun device) this field is in network order.
    // In host order it would be 0x00000800 the first two bytes (0000) are
    // the flags field, the next two byte (0800 are the protocol field, in this
    // case IP): http://www.mjmwired.net/kernel/Documentation/networking/tuntap.txt 

    const struct iphdr *ip_hdr = (const struct iphdr *)(buf + sizeof(struct tunhdr));

    unsigned short tun_info[2];
    tun_info[0] = 0; //flags
    tun_info[1] = ip_hdr->version == 6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);
    memcpy(&buf[sizeof(struct tunhdr) - TUNTAP_OFFSET], tun_info, TUNTAP_OFFSET);

    /*
    // Flags 2 bytes
    buf[0] = 0x08;
    buf[1] = 0x00;
    // Proto 2 bytes
    buf[2] = 0x00;
    buf[3] = 0x00;
    */

    // If getForwardPortsFlag(), replace src IP with gateway's private IP, and replace port number.
    /*
    if( getForwardPortsFlag() && (gw != NULL) )
    {
        struct ethhdr   *eth_hdr;
        struct iphdr    *ip_hdr;
        struct tcphdr   *tcp_hdr;

        tun_hdr = (struct tunhdr *)buf;
        ip_hdr = (struct iphdr *)(buf + sizeof(struct tunhdr));
        tcp_hdr = (struct tcphdr *)(buf + sizeof(struct tunhdr) + sizeof(struct iphdr));

        //print_iphdr(ip_hdr, NULL);
        //print_tcphdr(tcp_hdr, NULL);

        // We know they're using TCP for the buswatch traffic, and we also know the assigned port no.
        if ( ( ip_hdr->protocol == IPPROTO_TCP ) && ( ntohs(tcp_hdr->source) == gw->fwd_port ) )
        {
            char new_buf[MTU];

            int offset = 0;
            bufSize = bufSize - sizeof(struct tunhdr);

            // We need to prepend an ethernet header = sizeof the old packet + sizeof ethernet header
            // minus sizeof tunhdr

            if((rawsockfd = openRawsock(getInternalIF(), ETH_P_IP)) < 0)
            {  
                ERROR_MSG("socket() failed");
                return FAILURE;
            }

            // Copy in Source MAC address
            struct ifreq ifr;
            char *src_mac_addr = internalIFGetMAC(&ifr);

            // Copy in our MAC address as the source
            memcpy(eth_hdr.h_source, src_mac_addr, ETH_ALEN);

            // Copy in the saved off MAC source as the destination
            memcpy(eth_hdr.h_dest, dmz_source_mac, ETH_ALEN);

            unsigned short eth_type = htons(ETH_P_IP);
            memcpy(&eth_hdr.h_proto, &eth_type, sizeof(eth_type));

            //print_ethhdr(&eth_hdr, NULL);

            // Copy in the eth_hdr we constructed
            memcpy(new_buf, &eth_hdr, sizeof(struct ethhdr));
            offset += sizeof(struct ethhdr);

            // Copy over contents of buf to tmp_buf so we can prepend eth_hdr
            // Don't include the tunhdr in tmp_buf
            memcpy(new_buf, buf + sizeof(struct tunhdr), MTU - sizeof(struct tunhdr));

            // Update the IP/TCP Header pointers
            ip_hdr = (struct iphdr *)(new_buf);
            tcp_hdr = (struct tcphdr *)(new_buf + sizeof(struct iphdr));


            // Update checksum of the TCP header
            tcp_hdr->check = htons(updateCsum((u_int32_t)ntohl(inet_addr(getControllerIP())), (u_int32_t)ntohl(ip_hdr->saddr), (u_int16_t)ntohs(tcp_hdr->check)));

            // Update checksum of IP header
            ip_hdr->check = htons(updateCsum((u_int32_t)ntohl(inet_addr(getControllerIP())), (u_int32_t)ntohl(ip_hdr->saddr), (u_int16_t)ntohs(ip_hdr->check)));

            // Replace the source IP address to that of our own so packets flow back to controller
            unsigned int n_controller_ip = inet_addr(getControllerIP());
            memcpy(&ip_hdr->saddr, &n_controller_ip, sizeof(n_controller_ip));

            //print_ethhdr(&eth_hdr, NULL);
            //print_iphdr(ip_hdr, NULL);
            //print_tcphdr(tcp_hdr, NULL);

    */


#ifdef ARE_BUFFERING
    // Put packets in the buffer
    if( reOrderPacket(&buf[sizeof(struct tunhdr) - TUNTAP_OFFSET], (bufSize - sizeof(struct tunhdr) + TUNTAP_OFFSET), tunfd, pktSeqNo, codeLen) < 0) 
    {
        DEBUG_MSG("reOrderPacket(): failed to put packet in queue");
        return FAILURE;
    }
#else
    // Single threaded version
    if( write(tunfd, &buf[sizeof(struct tunhdr) - TUNTAP_OFFSET], (bufSize-sizeof(struct tunhdr) + TUNTAP_OFFSET)) < 0 )
    {
        ERROR_MSG("write() to tunfd failed");
        return FAILURE;
    }
#endif
    
    return SUCCESS;
} // End function handleOutboundPacket

/*
 * Open a UDP socket for receiving tunnel packets.
 */
static int openDataSocket()
{
    int sockfd;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family     = AF_INET6;
    hints.ai_socktype   = SOCK_DGRAM;
    hints.ai_protocol   = 0;
    hints.ai_flags      = AI_PASSIVE | AI_NUMERICSERV;

    struct addrinfo *addrinfo = 0;
    int res = getaddrinfo(0, WIROVER_PORT_STR, &hints, &addrinfo);
    if(res != 0) {
        DEBUG_MSG("getaddrinfo failed: %s", gai_strerror(res));
        return FAILURE;
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype,
            addrinfo->ai_protocol);
    if(sockfd < 0) {
        ERROR_MSG("socket() failed");
        goto free_and_exit;
    }

    if(bind(sockfd, (struct sockaddr *)addrinfo->ai_addr,
                addrinfo->ai_addrlen) < 0) {
        ERROR_MSG("bind() failed");
        goto close_and_exit;
    }

    freeaddrinfo(addrinfo);

    // Success
    return sockfd;

close_and_exit:
    close(sockfd);

free_and_exit:
    freeaddrinfo(addrinfo);

    return FAILURE;
}

/*
 * H A N D L E  P A C K E T S
 *
 * Function to handle all packets
 *
 */
int handlePackets(int tunfd)
{
    fd_set readSet;

    char     buf[MTU];
    int     bufSize, sockfd, fwd_sockfd;

    // Create a UDP socket (bound to internal interface so
    // that the IP/UDP headers are automatically stripped off
    // Sockfd will sit and listen for incoming connections from gateways
    sockfd = openDataSocket();
    if(sockfd < 0) {
        DEBUG_MSG("openDataSocket() failed");
        return FAILURE;
    }

    sprintf(local_buf, "\nListening for gateway traffic on port: %d\n", WIROVER_PORT);
    GENERAL_MSG(local_buf);

    sprintf(local_buf, "Listening for control channel traffic on port: %d\n", CONTROL_PORT);
    GENERAL_MSG(local_buf);

    sprintf(local_buf, "Listening for transfer traffic on port: %d\n", TRANSFER_PORT);
    GENERAL_MSG(local_buf);

    sprintf(local_buf, "Listening for UDP Ping traffic on port: %d\n", UDP_PING_PORT);
    GENERAL_MSG(local_buf);

    // Bind the listening socket to the internal interface
    //struct ifreq ifr;
    //memset(&ifr, 0, sizeof(struct ifreq));
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, internal_if, IFNAMSIZ) < 0) 
    {
        ERROR_MSG("setsockopt() SO_BINDTODEVICE failed");
        return FAILURE;
    }

    // If getForwardPortsFlag(), create raw socket to listen for all incoming connections
    if(getForwardPortsFlag())
    {
#ifdef FWD_SOCKFD_TCP
        if((fwd_sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
#else
        if((fwd_sockfd = openRawsock(getInternalIF(), ETH_P_IP)) < 0)
#endif
        {
            ERROR_MSG("fwd_sockfd failed");
        }

#ifdef FWD_SOCKFD_TCP
        // Set maximum segment size
        int maxseg = TCP_MSS_VALUE;
        if (setsockopt(fwd_sockfd, IPPROTO_TCP, TCP_MAXSEG, &maxseg, sizeof(maxseg)) < 0) 
        {
            ERROR_MSG("setsockopt() TCP_MAXSEG failed");
        }

        // Listen to incoming connections
        if ( listen(fwd_sockfd, 10) < 0 )
        {
            ERROR_MSG("fwd_sockfd listen failed");
        }
#endif
    }


    while( 1 )
    {
        // Setup read descriptors
        FD_ZERO(&readSet);
        FD_SET(tunfd, &readSet);
        FD_SET(sockfd, &readSet);
        //FD_SET(trans_sockfd, &readSet);

        if(getForwardPortsFlag())
        {
            FD_SET(fwd_sockfd, &readSet);
        }

        // A failsafe for the race condition (see below)
        if ( getQuitFlag() )
        {
            shutdownController();
            return SUCCESS;
        }

        // Since orig_set has nothing in it, then pselect should return
        // when SIGINT, or SIGTERM is delivered
        sigemptyset(&orig_set);

        // We must use pselect, since we want SIGINT/SIGTERM to interrupt
        // and be handled
        int select_rtn = pselect(FD_SETSIZE, &readSet, NULL, NULL, NULL, &orig_set);

        // Race condition

        if ( getQuitFlag() )
        {
            shutdownController();
            return SUCCESS;
        }

        // Race condition: quit flag may be set at this point, which means
        // we need the failsafe check above

        // Make sure select didn't fail
        if( select_rtn < 0 && errno == EINTR)
        {  
            continue;
        }
        
        // Send packets back to a wigateway
        if( FD_ISSET(tunfd, &readSet) ) 
        {
            if( (bufSize = read(tunfd, buf, (sizeof(buf)-TUNTAP_OFFSET))) < 0)
            {
                ERROR_MSG("reading from tunfd failed");
            }
            else
            {
                stripePacket(sockfd, buf, bufSize, TUNTAP_OFFSET);
            }
        }    

        // Receive packets from a WiGateway and send them out
        if( FD_ISSET(sockfd, &readSet) ) 
        {
            if ( handleOutboundPacket(sockfd, tunfd) < 0 )
            {
                DEBUG_MSG("handleOutboundPacket() failed");
            }
        }

        // Handle packets coming in from the outside world
        if ( getForwardPortsFlag() && FD_ISSET(fwd_sockfd, &readSet) )
        {
            forwardPacket(fwd_sockfd, sockfd);
        }
    } // End while( 1 )

    return SUCCESS;
} // End function int handlePackets()

/**
 * Uses the most recent sequence number sent on the interface
 * to update the number of lost packets over that interface.
 */
void updatePacketLoss(struct link* link, unsigned short curr_seq_no) {
    if(link->seq_no_valid) {
        unsigned short lost = curr_seq_no - link->local_seq_no_in;

        if(lost > MAX_PACKET_LOSS) {
            link->out_of_order_packets++;
        } else {
            link->packets_lost += lost;
            link->local_seq_no_in = curr_seq_no + 1;
        }
    } else {
        // On the first packet sent over a link, we need to synchronize the
        // sequence numbers and not count losses.
        link->local_seq_no_in = curr_seq_no + 1;
        link->seq_no_valid = 1;
    }
}

void segfaultHandler(int signo)
{
    if(signo == SIGSEGV) {
        log_backtrace();
        system("shutdown -r now segfault in wicontroller");
        exit(1);
    }
}


/*
 * M A I N
 * 
 * Main function
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int main(int agrc, char *argv[])
{
#ifdef WITH_MYSQL
    // Open the gateway database
    if(gw_init_db() == FAILURE) {
        DEBUG_MSG("Warning: not connected to mysql database");
    }
#endif
	
    // Set the appropriate signal handler functions
    setSigHandlers();
    signal(SIGSEGV, segfaultHandler);

    // Block these signals, we want pselect() to catch them
    // Clear the block set
    sigemptyset(&block_set);         
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    sigprocmask(SIG_BLOCK, &block_set, NULL);

    // Open the log file
    if ( openLogs() < 0 )
    {
        DEBUG_MSG("openLogs() failed");
    }

    sprintf(local_buf, "\nLaunching WiController (version %.2f) %s\n", VERSION, getTime());
    GENERAL_MSG(local_buf);

    // Create the control channel, must be done before parseConfigFileCont()
    // deprecated, hopefully
    //createControlChannel();

    // Parse the options in /etc/wirover
    if ( parseConfigFileCont() < 0 )
    {
        ERROR_MSG("parseConfigFileCont() failed");
        return FAILURE;
    }
    
    if(setSchedPriority(SCHED_PRIORITY) == FAILURE) {
        // not a critical failure
        DEBUG_MSG("Warning: setSchedPriority failed");
    }

    // Configuring the control channel must happen after parsing the config file.
    configureControlChannel();

    // Create the tunnel device
    struct tunnel *myTunnel = NULL;
    if ( (myTunnel = tunnelCreate()) == NULL )
    {
        DEBUG_MSG("tunnelCreate() failed");
    }

    int TunFD = tunnelInit(myTunnel);
    setTunnelDescriptor(TunFD);
    initSelectInterface(myTunnel->remotePort);
    
    system("/usr/bin/wicontroller_config");

    // Previously initiated and accepted exchanges bypass rule checking
    // Allow unlimited outbound traffic
    // system("/sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");
    // system("/sbin/iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");

    // Open up control channel port
    iptables("A", "INPUT", "tcp", "any", 8082);

    // Open up udp ping port
    iptables("A", "INPUT", "udp", "any", 8084);

    // Drop all other traffic
    // system("/sbin/iptables -A INPUT -j DROP");

#ifdef ARE_BUFFERING
    // Create thread to send packets
    createReOrderThread();

    // Initialize the packet_array to NULL
    reOrderInit();
#endif

    struct ping_server_info pingInfo;
	pingInfo.local_port = UDP_PING_PORT;

    if(startPingServerThread(&pingInfo) == FAILURE) {
        DEBUG_MSG("startPingServerThread() failed");
        return FAILURE;
    }

    struct bw_server_info bwInfo;
    bwInfo.local_port = ACTIVE_BW_PORT;
    bwInfo.timeout = ACTIVE_BW_TIMEOUT;

    if(startBandwidthServerThread(&bwInfo) == FAILURE) {
        DEBUG_MSG("startBandwidthServerThread() failed");
        return FAILURE;
    }

    // Create control channel thread
    createContChanThread();
    
    // Create passive bandwidth thread
    startPassiveThread();

#ifdef WITH_MYSQL
    setPassiveCallback(gw_update_passive);
#endif

    // Process packets
    if ( handlePackets(TunFD) == FAILURE )
    {
        return FAILURE;
    }

#ifdef WITH_MYSQL
    gw_close();
#endif

    closeFileHandles();

    return SUCCESS;
} // End function int main()
