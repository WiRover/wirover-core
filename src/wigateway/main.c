/*
 * M A I N . C
 *
 * This file manages the packet encapsulation/tunneling to the 
 * WiROVER controller, essentially what it does is create all
 * necessary worker threads and handles interception of packets
 * going to controller and coming from the controller.
 *
 * The main() function mostly doest setup of the entire program
 * including creating worker threads, reading configuration,
 * and setting up parameters.  It then calls off to handlePackets()
 * which will intercept packets in user space.  Packets coming from
 * the internal network will be NAT'd and then send to then tun device
 * which encapsulates them in a UDP header.  Outgoing Packets will also have 
 * our own special header on top of that.  Packets coming from the
 * controller will be decapsulated (UDP/special headers ripped off)
 * and then be DeNAT'd and fowarded to the client.
 *
 * The handlePackets() function loops indefintely until the gateway
 * catches a SIGINT or SIGTERM, when this happens, shutdownGateway()
 * will be called which will do all necessary cleanup.
 *
 */

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>

#include "../common/active_bw.h"
#include "../common/contChan.h"
#include "../common/handleTransfer.h"
#include "../common/tunnelInterface.h"
#include "../common/packet_debug.h"
#include "../common/passive_bw.h"
#include "../common/reOrderPackets.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
//#include "../common/evdo_buffer.h"
#include "../common/udp_ping.h"
#include "../common/utils.h"
#include "../common/special.h"
#include "pcapSniff.h"
#include "selectInterface.h"
#include "scan.h"
#include "ppp.h"
#include "netlink.h"
#include "transfer.h"
#include "gpsHandler.h"

static uint32_t tunnel_ip;
static unsigned long long total_bytes_recvd = 0;
static sigset_t orig_set; //, block_set;

static char local_buf[MAX_LINE];
static unsigned short dmz_orig_port = 0;

//static pthread_t    sigintThread;

// Function Header Definitions
int handleInboundPacket(int tunfd, int incoming_sockfd);
int handleOutboundPacket(int tunfd, struct tunnel *tun);
int handleNoControllerPacket(int tunfd, fd_set readSet);

// Used for IPSEC information
// static ipsec_req_t ipsr;

/*
 * O P E N  C O N T R O L L E R  S O C K E T
 *
 * Returns (int)
 *      Success: a socket file descriptor
 *      Failure: -1
 *
 */
int openControllerSocket(struct tunnel *tunnel)
{
    int sockfd;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family     = AF_INET;
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
    } else {
        DEBUG_MSG("Listening for return traffic on port: %d", WIROVER_PORT);
    }

    freeaddrinfo(addrinfo);

    // Success
    return sockfd;

close_and_exit:
    close(sockfd);

free_and_exit:
    freeaddrinfo(addrinfo);

    return FAILURE;
} // End function int openControllerSocket()


/*
 * H A N D L E  P A C K E T S
 *
 * Returns: zero on success, less than zero on failure
 *
 */
int handlePackets(int tunfd, struct tunnel *tun)
{
    // The File Descriptor set to add sockets to
    fd_set readSet;
    int rtn;

    int incoming_sockfd = -1;
    
    // Set up the general traffic listening socket
    if( (incoming_sockfd = openControllerSocket(tun)) < 0 )
    {
        DEBUG_MSG("openControllerSocket() failed");
        destroyScanThread();
        tunnelCleanup();
        return FAILURE;
    }

    /* Set up the UDP Ping listening socket
    struct sockaddr_in udpPingAddr;
    int rcv_udp_ping_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    memset(&udpPingAddr, 0, sizeof(struct sockaddr_in));
    udpPingAddr.sin_family         = AF_INET;
    udpPingAddr.sin_port        = htons((unsigned short)UDP_PING_PORT);
    udpPingAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Sockfd will sit and listen for incoming connections
    if( bind(rcv_udp_ping_sockfd, (struct sockaddr *)&udpPingAddr, sizeof(struct sockaddr_in)) < 0)
    {   
        ERROR_MSG("bind() sockfd ");
        close(rcv_udp_ping_sockfd);
        return FAILURE;
    }
    */

    //int netlink_sockfd = createNetLinkSocket();

    while( 1 )
    {
        // Zero out the file descriptor set
        FD_ZERO(&readSet);

        // Add the read file descriptor to the set ( for listening with a controller )
        FD_SET(incoming_sockfd, &readSet);

        // Add the tunnel device to the set of file descriptor set ( with or without using the controller )
        FD_SET(tunfd, &readSet);

        // Add the UDP Ping response socket to the file descriptor set
        //FD_SET(rcv_udp_ping_sockfd, &readSet);

        // Add the netlink socket to the file descriptor set
        //netlink_sockfd = getNetLinkSocket();
        //FD_SET(netlink_sockfd, &readSet);

        // Add raw sockets to file descriptor set (for listening with no controller ) 
        struct link *ife;

        // Open up raw sockets for specified outgoing devices ( list should already be built )
        for ( ife = head_link__ ; ife ; ife = ife->next  )
        {
            FD_SET(ife->sockfd, &readSet);
        }

        // A failsafe for the race condition (see below)
        if ( getQuitFlag() )
        {
            shutdownGateway();
            return SUCCESS;
        }
    
        // Pselect should return
        // when SIGINT, or SIGTERM is delivered, but block SIGALRM
        sigemptyset(&orig_set);
        sigaddset(&orig_set, SIGALRM);

        // We must use pselect, since we want SIGINT/SIGTERM to interrupt
        // and be handled
        rtn = pselect(FD_SETSIZE, &readSet, NULL, NULL, NULL, &orig_set);
        //DEBUG_MSG("pselect() main.c returned\n");

        // Race condition
        if ( getQuitFlag() )
        {
            shutdownGateway();
            return SUCCESS;
        }
        
        // Make sure select didn't fail
        if( rtn < 0 && errno == EINTR) 
        {
            DEBUG_MSG("select() failed");
            continue;
        }

        // This is how we receive packets from the controller
        if( FD_ISSET(incoming_sockfd, &readSet) ) 
        {
            //printf("incoming_sockfd %d is set.\n", incoming_sockfd);
            //fflush(stdout);

            if ( handleInboundPacket(tunfd, incoming_sockfd) < 0 ) 
            {
                continue;
            }
        }

        // If packet is going to controller (tunnel is virtual device)
        if( FD_ISSET(tunfd, &readSet) ) 
        {
            //printf("tunfd is set\n");
            if ( handleOutboundPacket(tunfd, tun) < 0 ) 
            {
                // If -1 is returned, we couldn't find an interface to send out of
                continue;
            }
        }

        /* If packet is going to controller (tunnel is virtual device)
         * This should be handled by the netlink thread now
        if( FD_ISSET(netlink_sockfd, &readSet) ) 
        {
            //printf("netlink_sockfd is set\n");
            if ( handleNetLinkPacket() < 0 ) 
            {
                // If -1 is returned, we couldn't find an interface to send out of
                continue;
            }
        }
        */
    } // while( 1 )

    return SUCCESS;
} // End function int handlePackets()


/*
 * H A N D L E  N O  C O N T R O L L E R  P A C K E T
 *
 * Returns: 
 *      Success: 0
 *      Failure: -1
 *
 */
// TODO: this function needs to be updated to use the struct tunhdr and TUNTAP_OFFSE
int handleNoControllerPacket(int tunfd, fd_set readSet) 
{
    int		        bufSize, rtn;
    char            buffer[MTU];
    unsigned short 	old_sum, new_sum;
    uint32_t        old_ip, new_ip;

    struct iphdr 	*ip_hdr;
    struct udphdr 	*udp_hdr;
    struct tcphdr 	*tcp_hdr;

    // This is how we receive packets if not using a Controller
    struct link *ife = head_link__;

    unsigned int fromlen = sizeof(struct sockaddr_in);
    struct sockaddr_in from;

    // Open up raw sockets for specified outgoing devices
    for ( ife = head_link__; ife ; ife = ife->next  )
    {
        // Check to see if this particular socket is set
        if ( FD_ISSET(ife->sockfd, &readSet) ) 
        {
            int offset;
            if( ife->stats.flags & IFF_POINTOPOINT )
            {
                offset = 4;
                bufSize = recvfrom(ife->sockfd, &buffer[4], (MTU-4), 0, (struct sockaddr *)&from, &fromlen);
                ife->bytes_recvd += bufSize;

                sprintf(local_buf, "Bytes recvd on %s: %llu\n", ife->ifname, ife->bytes_recvd);
                STATS_MSG(local_buf);
            }
            else
            {
                offset = ETH_HLEN;
                bufSize = recvfrom(ife->sockfd, buffer, MTU, 0, (struct sockaddr *)&from, &fromlen);
                ife->bytes_recvd += bufSize;

                sprintf(local_buf, "Bytes recvd on %s: %llu\n", ife->ifname, ife->bytes_recvd);
                STATS_MSG(local_buf);
            }

            if( bufSize < 0) 
            {
                ERROR_MSG("recvfrom failed");
            } 
            else 
            {
                ip_hdr = (struct iphdr *)(buffer + offset);
                memcpy(&old_ip, &ip_hdr->daddr, sizeof(old_ip));
                memcpy(&old_sum, &ip_hdr->check, sizeof(old_sum));

                if ( old_ip == ULONG_MAX )
                {
                    // Don't forward broadcast packets (hack for wimax)
                    continue;
                }

                // IP checksum
                new_ip = tunnel_ip;
                new_sum = htons(updateCsum(ntohl(new_ip), ntohl(old_ip), ntohs(old_sum)));
                memcpy(&ip_hdr->daddr, &new_ip, sizeof(ip_hdr->daddr));
                memcpy(&ip_hdr->check, &new_sum, sizeof(unsigned short));

                //print_ip(tunnel_ip);

                if(ip_hdr->protocol == IPPROTO_UDP)
                {
                    udp_hdr = (struct udphdr *)(buffer + offset + ip_hdr->ihl*4);
                    memcpy(&old_sum, &udp_hdr->check, sizeof(unsigned short));
                    new_sum = htons(updateCsum(ntohl(new_ip), ntohl(old_ip), ntohs(old_sum)));
                    memcpy(&udp_hdr->check, &new_sum, sizeof(unsigned short));
                }
                else if(ip_hdr->protocol == IPPROTO_TCP)
                {
                    tcp_hdr = (struct tcphdr *)(buffer + offset + ip_hdr->ihl*4);
                    memcpy(&old_sum, &tcp_hdr->check, sizeof(unsigned short));
                    new_sum = htons(updateCsum(ntohl(new_ip), ntohl(old_ip), ntohs(old_sum)));
                    memcpy(&tcp_hdr->check, &new_sum, sizeof(unsigned short));
                }

                // This is needed to notify the tun0 that was are passing an IP packet
                buffer[offset - 4] = 0x08; // Have to pass in the IP proto as first two bytes
                buffer[offset - 3] = 0x00;
                buffer[offset - 2] = 0x08; // Something messed up with tun/tap drive 
                buffer[offset - 1] = 0x00;

                if( ife->stats.flags & IFF_POINTOPOINT )
                {
                    if( (rtn = write(tunfd, buffer, (bufSize+4))) < 0) 
                    {
                        ERROR_MSG("writting to tunnel failed");
                    }
                }
                else
                {
                    if( (rtn = write(tunfd, &buffer[10], (bufSize-10))) < 0) 
                    {
                        ERROR_MSG("writting to tunnel");
                    }
                }
            }
        }
    }

    return SUCCESS;
} // End function int handleNoControllerPacket()


/*
 * H A N D L E  I N B O U N D  P A C K E T
 *
 * Handle packets coming from the controller.
 *
 * Returns: 
 *      Success: 0
 *      Failure: -1
 *
 */
int handleInboundPacket(int tunfd, int incoming_sockfd) 
{
    struct  tunhdr n_tun_hdr;
    int     bufSize;
    char    buffer[MTU];

    struct sockaddr_storage     from;
    unsigned    fromlen = sizeof(from);

    bufSize = recvfrom(incoming_sockfd, buffer, sizeof(buffer), 0, 
            (struct sockaddr *)&from, &fromlen);
    if(bufSize < 0) {
        ERROR_MSG("recvfrom() failed");
        return FAILURE;
    }

    struct timeval arrival_time;
    if(ioctl(incoming_sockfd, SIOCGSTAMP, &arrival_time) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&arrival_time, 0);
    }

    total_bytes_recvd += bufSize;  

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, buffer, sizeof(struct tunhdr));

    // Copy temporary to host format
    unsigned int h_seq_no = ntohl(n_tun_hdr.seq_no);
    
    //unsigned short h_node_id = ntohs(n_tun_hdr.node_id);
    unsigned short h_link_id = ntohs(n_tun_hdr.link_id);

    struct link* ife = searchLinksById(head_link__, h_link_id);
    if(ife) {
        ife->bytes_recvd += bufSize;

        unsigned short h_local_seq_no = ntohs(n_tun_hdr.local_seq_no);
    
        unsigned short lost = h_local_seq_no - ife->local_seq_no_in;
        if(lost > MAX_PACKET_LOSS) {
            ife->out_of_order_packets++;
        } else {
            ife->packets_lost += lost;
            ife->local_seq_no_in = h_local_seq_no + 1;
        }

        struct tunnel_measurement tmeas;
        if(finishTunnelMeasurement(&tmeas, ife, &n_tun_hdr, bufSize, 
                    &arrival_time)) {
            STATS_MSG("Tunnel measurement for link %u (%s): latency %f us, "
                    "bandwidth %f bps (age %u)",
                h_link_id, ife->network, tmeas.latency, 
                tmeas.bandwidth, ntohl(n_tun_hdr.service));
        }

        updateTunnelTimestamps(ife, &n_tun_hdr, bufSize, &arrival_time);
    }

    // This is needed to notify tun0 we are passing an IP packet
    // Have to pass in the IP proto as last two bytes in ethernet header
    //
    // Copy in four bytes, these four bytes represent the four bytes of the
    // tunnel header (added by the tun device) this field is in network order.
    // In host order it would be 0x00000800 the first two bytes (0000) are
    // the flags field, the next two byte (0800 are the protocol field, in this
    // case IP): http://www.mjmwired.net/kernel/Documentation/networking/tuntap.txt

    const struct iphdr *ip_hdr = (const struct iphdr *)(buffer + sizeof(struct tunhdr));

    unsigned short tun_info[2];
    tun_info[0] = 0; //flags
    tun_info[1] = ip_hdr->version == 6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);

    memcpy(&buffer[sizeof(struct tunhdr) - TUNTAP_OFFSET], tun_info, TUNTAP_OFFSET);
    
    // If fwd_ports_enabled, check if TCP packet falls within range.
    // If so, replace the destination IP with the DMZ host specified in the config file.
    // Also replace the port number with DMZ port specified in config file.

    /*
    if( getForwardPortsFlag() )
    {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + sizeof(struct tunhdr) + sizeof(struct iphdr));

        // FIXME: Add IPv6 support if you want port forwarding.
        if(ip_hdr->version == 4 && ip_hdr->protocol == IPPROTO_TCP)
        {
            // If packet falls within port range, overwrite IP and port numbers.
            if( (ntohs(tcp_hdr->dest) >= getForwardPortStart() ) && (ntohs(tcp_hdr->dest) <= getForwardPortEnd() ) )
            {
                GENERAL_MSG("Forwarding packet (%d bytes) to IP: ", bufSize);

                uint32_t dmz_ip = getDmzHostIP();
                short dmz_port = getDmzHostPort();

                // Update checksum of TCP header
                tcp_hdr->check = htons(updateCsumIPPort(ntohs(tcp_hdr->check), ntohl(ip_hdr->daddr), 
                    ntohs(tcp_hdr->dest), ntohl(dmz_ip), dmz_port));

                // Copy over the TCP port number that we want to send to
                dmz_orig_port = ntohs(tcp_hdr->dest);
                tcp_hdr->dest = htons(dmz_port);

                // Update checksum of IP header
                ip_hdr->check = htons(updateCsum(ntohl(dmz_ip), ntohl(ip_hdr->daddr), ntohs(ip_hdr->check)));

                // Copy over the IP address that we want to send to
                ip_hdr->daddr = dmz_ip;
                printIp(ip_hdr->daddr);
                GENERAL_MSG(" Port: %d", ntohs(tcp_hdr->dest));

                //print_iphdr(ip_hdr, NULL);
                //print_tcphdr(tcp_hdr, NULL);
            }
        }
    }
    */

#ifdef ARE_BUFFERING
    // Multi-thread version
    if( reOrderPacket(&buffer[sizeof(struct tunhdr)-TUNTAP_OFFSET], 
        (bufSize-sizeof(struct tunhdr)+TUNTAP_OFFSET), 
            tunfd, h_seq_no, CODELEN) < 0) 
    {
        return FAILURE;
    }
#else
    if( (rtn = write(tunfd, &buffer[sizeof(struct tunhdr)-TUNTAP_OFFSET], 
                    (bufSize-sizeof(struct tunhdr)+TUNTAP_OFFSET))) < 0) 
    {
        ERROR_MSG("write() failed");
    }
#endif

    return SUCCESS;
} // End function int handleInboundPacket()


/*
 * H A N D L E  O U T B O U N D  P A C K E T
 *
 * Sends packets out to the internet (either straight or to the controller)
 *
 * Returns: 
 *      Success: 0
 *      Failure: -1
 *
 */
int handleOutboundPacket(int tunfd, struct tunnel * tun) 
{
    int bufSize, rtn;
    char buffer[MTU];

    if( (bufSize = read(tunfd, buffer, MTU)) < 0) 
    {
        ERROR_MSG("read packet failed");
    } 
    else 
    {
        // If FILTERING is enabled, check that client address is allowed prior to sending packet
        if( (getWebFilterFlag() == 1) && (isClientAllowed(buffer, bufSize) == 0))
        {
            return SUCCESS;
        }

        struct iphdr    *ip_hdr = (struct iphdr *)(buffer + TUNTAP_OFFSET);
        struct tcphdr   *tcp_hdr = (struct tcphdr *)(buffer + TUNTAP_OFFSET + (ip_hdr->ihl * 4));

        // If client is not authorized, redirect to agreement page

        // If DMZHOSTIP and DMZHOSTPORT, replace IP with gateway's private IP with DMZHOSTIP and port number with DMZHOSTPORT.
        if( getForwardPortsFlag() )
        {
            // If packet is TCP, originates from DMZHOSTIP on DMZHOSTPORT, change IP/PORT accordingly.
            // FIXME: Add IPv6 support if you want port forwarding.
            if (ip_hdr->version == 4 && ip_hdr->protocol == IPPROTO_TCP &&
                    ip_hdr->saddr == getDmzHostIP() && ntohs(tcp_hdr->source) == getDmzHostPort() )
            {
                // Update checksum of the TCP header
                tcp_hdr->check = htons(updateCsumIPPort(ntohs(tcp_hdr->check), ntohl(ip_hdr->saddr),
                            getDmzHostPort(), ntohl(tun->n_private_ip), dmz_orig_port));
                tcp_hdr->source = htons(dmz_orig_port);

                // Update checksum of IP header
                ip_hdr->check = htons(updateCsum(ntohl(tun->n_private_ip), ntohl(ip_hdr->saddr), ntohs(ip_hdr->check)));

                // Copy over the IP address that we want to send to into the source address
                //printf("tun_priv_ip: %d\n", tun_priv_ip);
                uint32_t tun_priv_ip = getTunPrivIP();
                memcpy(&ip_hdr->saddr, &tun_priv_ip, sizeof(tun_priv_ip));

                //print_iphdr(ip_hdr, NULL);
                //print_tcphdr(tcp_hdr, NULL);
            }
        }

        // Select interface and send
        if( (rtn = stripePacket(buffer, bufSize, getRoutingAlgorithm())) < 0)
        {
            ERROR_MSG("stripePacket() failed");
        }
    }

    return SUCCESS;
} // End function int handleOutboundPacket()

void segfaultHandler(int signo)
{
    if(signo == SIGSEGV) {
        log_backtrace();
        system("shutdown -r +1 segfault in wigateway");
        exit(1);
    }
}

/*
 * Read the controller address from the configuration file and configure the
 * ping thread to send pings to that address.
 */
static int configurePingThread()
{
    int result;

    struct addrinfo hints = {
        .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
        .ai_family = AF_INET,
    };

    // Get a sockaddr structure for the controller so that we can set it as the
    // target of UDP pings.
    struct addrinfo *addrinfo = 0;
    result = getaddrinfo(getControllerIP(), UDP_PING_PORT_STR, &hints, &addrinfo);
    if(result != 0) {
        DEBUG_MSG("getaddrinfo failed: %s (%s:%s)", gai_strerror(result),
                getControllerIP(), UDP_PING_PORT_STR);
        return FAILURE;
    }
    assert(addrinfo != 0 && addrinfo->ai_addr != 0);

    setUdpPingTarget(addrinfo->ai_addr, addrinfo->ai_addrlen);
    freeaddrinfo(addrinfo);

    return 0;
}

/*
 * M A I N
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int main(int argc, char *argv[])
{
    int rtn;

    // Set the appropriate signal handler functions
    setSigHandlers();
    signal(SIGSEGV, segfaultHandler);

    // Block these signals, we want pselect() to catch them
    /* Clear the block set
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    sigprocmask(SIG_BLOCK, &block_set, NULL);
    */

    // Open up /var/log/wirover and /var/log/wirover_stats
    if ( openLogs() < 0 )
    {
        DEBUG_MSG("openLogs() failed");
		shutdownGateway();
        return SUCCESS;
    }

    sprintf(local_buf, "logger -t \"WiRover Version: %.2f [%d]\" System Boot", VERSION, getPid());
    system(local_buf);
    DEBUG_MSG("Launching WiGateway (version %.2f) (pid: %d)", VERSION, getPid());

    // Parse /etc/wirover
    if ( parseConfigFileGW() < 0 )
    {
        DEBUG_MSG("parseConfigFile() failed");
        return FAILURE;
    }

    if(setSchedPriority(SCHED_PRIORITY) == FAILURE) {
        // not a critical failure
        DEBUG_MSG("Warning: setSchedPriority failed");
    }   

    struct ifreq ifr;
    if( !internalIFGetMAC(&ifr) ) {
        DEBUG_MSG("internalIFGetMAC failed");
        system("shutdown -r +1 rebooting due to unusual failure");
    }

    struct tunnel *tun;
    int tunfd = 0;

    if(getOpenDNS())
        genResolvDotConf();

	if( initGpsHandler() == FAILURE )
	{
		DEBUG_MSG("initGpsHandler() failed");
	}

    // Setup the tunnel structure
    if( (tun = tunnelCreate()) == NULL)
    {
        DEBUG_MSG("tunnelCreate() failed");
    }

	    // Create netlink thread
    if ( createNetLinkThread() == FAILURE ) 
    {
        DEBUG_MSG("createNetLinkThread() failed");
		shutdownGateway();
        return SUCCESS;
    }
    else 
    {
        DEBUG_MSG("Created NetLink Thread.");
    }

    char *controller_ip = getControllerIP();
    memcpy(tun->remoteIP, controller_ip, sizeof(tun->remoteIP));

/* 
    if ( createPPPThread() == FAILURE ) 
    {
        DEBUG_MSG("createPPPThread() failed");
		shutdownGateway();
        return SUCCESS;
    }
    else 
    {
        DEBUG_MSG("Created PPP Thread.");
    }
*/

    if(configurePingThread() == FAILURE) {
        DEBUG_MSG("configurePingThread() failed");
        shutdownGateway();
        return FAILURE;
    }

    struct ping_client_info pingInfo;
    pingInfo.interval = PING_INTERVAL;
    pingInfo.timeout = PING_TIMEOUT;

    if(startPingClientThread(&pingInfo) == FAILURE) {
        DEBUG_MSG("startPingClientThread() failed");
        shutdownGateway();
        return FAILURE;
    }

    registerPingCallback(&pingInfo, pingHandler);

    struct bw_client_info bwInfo;
    bwInfo.numBytes = ACTIVE_BW_BYTES;
    bwInfo.timeout = ACTIVE_BW_TIMEOUT;
    bwInfo.interval = ACTIVE_BW_INTERVAL;
    inet_pton(AF_INET, getControllerIP(), &bwInfo.remote_addr);
    bwInfo.remote_port = ACTIVE_BW_PORT;

    if(startBandwidthClientThread(&bwInfo) == FAILURE) {
        DEBUG_MSG("startBandwidthClientThread() failed");
        shutdownGateway();
        return FAILURE;
    }

    registerBandwidthCallback(&bwInfo, bandwidthHandler);
    
    // It seems that when we create a PPP thread we get bind() errors when
    // trying to ping, thus just call the function
    // connectEvdo();

    // Create the scan thread, must be before connecting control channel
    // so that timeouts work
    if ( createScanThread() == FAILURE )
    {
        DEBUG_MSG("createScanThread() failed");
		shutdownGateway();
        return SUCCESS;
    }
    else
    {
        DEBUG_MSG("Created Scanning Thread.");
    }

    int numTotalIf = countLinks(head_link__);

    // Sleep until we have some type of connection
    // struct timeval start, curr, result;
    // gettimeofday(&start, NULL);
    DEBUG_MSG("Waiting for interfaces to come up . .");

    // Register this gateway as soon as an interface comes up
    while( countActiveLinks(head_link__) == 0 )
    {
        //printf("getQuitFlag(): %d, getNumActiveInterfaces(): %d ", getQuitFlag(), getNumActiveInterfaces());
        //fflush(stdout);
        
        if ( getQuitFlag() ) 
        {
            shutdownGateway();
            return SUCCESS;
        }

        numTotalIf = countLinks(head_link__);

        // Don't use sleep() to sleep since it has problems with signals
        struct timeval sleep;
        sleep.tv_sec = 1;
        sleep.tv_usec = 0;
        select(0, NULL, NULL, NULL, &sleep);

/*
        gettimeofday(&curr, NULL);
        timersub(&start, &curr, &result);

        if ( result.tv_sec > CONNECT_WAIT_THRESHOLD )
        {
            DEBUG_MSG("Interfaces never came up . . . exiting.");
			shutdownGateway();
            return SUCCESS;
        }
*/
    }

    DEBUG_MSG("At least one interface came up.");

    int lease_attempt = 1;
    struct timeval sleep;
    sleep.tv_sec = 10;
    sleep.tv_usec = 0;

    // Get a lease
    sprintf(local_buf, "Getting Lease . . . attempt (%d) ", lease_attempt);
    DEBUG_MSG(local_buf);

    while ( getLease() < 0 )
    {
        if ( getQuitFlag() ) 
        {
            shutdownGateway();
            return SUCCESS;
        }

        // Don't use sleep() to sleep since it has problems with signals
        select(0, NULL, NULL, NULL, &sleep);

        if ( sleep.tv_sec < MAX_LEASE_TO )
        {
            sleep.tv_sec = sleep.tv_sec * 2;
        }
        else
        {
            sleep.tv_sec = MAX_LEASE_TO;
        }

        lease_attempt++;

        sprintf(local_buf, "Getting Lease . . . attempt (%d) ", lease_attempt);
        DEBUG_MSG(local_buf);
    }
    strncpy(tun->localIP, getTunLocalIP(), sizeof(tun->localIP));

    // TODO: I think we can wait until the links are up to do nat punches, but
    // this needs verification.  Uncomment below if necessary.  The thing is,
    // certain information (IP address of the link) is unavailable this early.
    
    // Punch holes in each of the interfaces in case 
    // there is a NAT on any of them (AT&T)
//    struct link *ife = head_link__;
//    while( ife != NULL )
//    {
//        uint32_t dAddr = 0;
//        inet_pton(AF_INET, tun->remoteIP, &dAddr);
//        if( natPunch(ife, dAddr, WIROVER_PORT, WIROVER_PORT) < 0 )
//        {
//            DEBUG_MSG("natPunch() failed");
//        }
//        ife = ife->next;
//    }

    // Tunnel interface file handle
    if ( (tunfd = tunnelInit()) < 0 )
    {
        DEBUG_MSG("tunnelInit() failed");
		shutdownGateway();
        return SUCCESS;
    }

    // Add the tunnel route
    addRoute("0.0.0.0", "0.0.0.0", 0, tun->name);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "route -A ip6 add default %s", tun->name);
    system(cmd);

    setTunnelDescriptor(tunfd);
    initSelectInterface(tun);
    
    // Set ups IPTables forwarding and NAT rules
    system("/usr/bin/wigateway_config > /dev/null 2>&1");
    DEBUG_MSG("Configuration complete.");

    if ( getNoCatFlag() )
    {
        system("rm /var/log/splashd");
        system("/usr/local/sbin/splashd > /var/log/splashd 2>/var/log/splashd_misc &");
        DEBUG_MSG("Started splashd.");
    }

#ifdef ARE_BUFFERING
    // Create thread to send packets in buffer
    if( createReOrderThread() == FAILURE )
    {
        DEBUG_MSG("createReOrderThread() failed");
        shutdownGateway();
        return SUCCESS;
    }
    else
    {
        DEBUG_MSG("Created ReOrder Thread.");
    }
#endif

#ifdef NETWORK_CODING
    
#endif
    // Process packets (both regular and control channels)
    //printf("controller_readfd: %d\n", controller_readfd);
    
    // Now that connectivity is established, start passive bandwidth measurements
    startPassiveThread();

    GENERAL_MSG("Detected interfaces:\n");
    dumpInterfaces(head_link__, "  ");


    // Initialize the BW estimation start time
    if ( (rtn = handlePackets(getTunnelDescriptor(), tun) < 0) )
    {
        DEBUG_MSG("handlePackets() failed");
    }

    return SUCCESS;
} // End function int main()


/* vim: set et:  */
