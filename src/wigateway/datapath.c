#include <errno.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include "configuration.h"
#include "debug.h"
#include "flowTable.h"
#include "interface.h"
#include "policyTable.h"
#include "packetBuffer.h"
#include "netlink.h"
#include "rwlock.h"
#include "sockets.h"
#include "tunnelInterface.h"

#ifndef SIOCGSTAMP
# define SIOCGSTAMP 0x8906
#endif
#define TUNTAP_OFFSET 4


static struct buffer_storage *packet_buffer[PACKET_BUFFER_SIZE];

int handleInboundPacket(int tunfd, int incoming_sockfd);
int handleOutboundPacket(int tunfd, struct tunnel *tun);
int handleNoControllerPacket(int tunfd, fd_set readSet);
int handlePackets();

static int              running = 0;
static pthread_t        data_thread;
static int              data_socket = -1;

int start_data_thread()
{
    if(running) {
        DEBUG_MSG("Data thread already running");
        return 0;
    }
 
    data_socket = udp_bind_open(get_data_port(), 0);
    if(data_socket == FAILURE) {
        DEBUG_MSG("Data thread cannot start due to failure");
        return FAILURE;
    }

    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result = pthread_create(&data_thread, &attr, handlePackets, 0);
    if(result != 0) {
        ERROR_MSG("Creating thread failed");
        close(data_socket);
        data_socket = -1;
        return FAILURE;
    }

    running = 1;

    pthread_attr_destroy(&attr);
    return 0;
}

int handlePackets()
{
    // The File Descriptor set to add sockets to
    struct tunnel *tun = getTunnel();
    fd_set read_set;
    sigset_t orig_set;

    initPacketBuffer(packet_buffer);

    int incoming_sockfd = -1;
    
    // Set up the general traffic listening socket
    if( (incoming_sockfd = udp_bind_open(get_data_port(), NULL)) == FAILURE )
    {
        DEBUG_MSG("openControllerSocket() failed");
        return FAILURE;
    }

    //Clear outData file
    FILE *ofp;
    ofp = fopen("outData.dat", "w");
    if (ofp == NULL) {
        ERROR_MSG("fopen() Failed");
        return FAILURE;
    }
    fclose(ofp);

    while( 1 )
    {
        // Zero out the file descriptor set
        FD_ZERO(&read_set);

        // Add the read file descriptor to the set ( for listening with a controller )
        FD_SET(incoming_sockfd, &read_set);

        // Add the tunnel device to the set of file descriptor set ( with or without using the controller )
        FD_SET(tun->tunnelfd, &read_set);

        // Pselect should return
        // when SIGINT, or SIGTERM is delivered, but block SIGALRM
        sigemptyset(&orig_set);
        sigaddset(&orig_set, SIGALRM);

        // Add raw sockets to file descriptor set (for listening with no controller ) 
        //struct link *ife;

        // Open up raw sockets for specified outgoing devices ( list should already be built )
        //TODO: Handle these in netlink
        /*for ( ife = head_link__ ; ife ; ife = ife->next  )
        {
            FD_SET(ife->sockfd, &read_set);
        }*/

        // We must use pselect, since we want SIGINT/SIGTERM to interrupt
        // and be handled
        int rtn = pselect(FD_SETSIZE, &read_set, NULL, NULL, NULL, &orig_set);
        //DEBUG_MSG("pselect() main.c returned\n");
        // Make sure select didn't fail
        if( rtn < 0 && errno == EINTR) 
        {
            DEBUG_MSG("select() failed");
            continue;
        }

        // This is how we receive packets from the controller
        if( FD_ISSET(incoming_sockfd, &read_set) ) 
        {
            //printf("incoming_sockfd %d is set.\n", incoming_sockfd);
            //fflush(stdout);

            if ( handleInboundPacket(tun->tunnelfd, incoming_sockfd) < 0 ) 
            {
                continue;
            }
        }

        // If packet is going to controller (tunnel is virtual device)
        if( FD_ISSET(tun->tunnelfd, &read_set) ) 
        {
            //printf("tunfd is set\n");
            if ( handleOutboundPacket(tun->tunnelfd, tun) < 0 ) 
            {
                // If -1 is returned, we couldn't find an interface to send out of
                continue;
            }
        }

    } // while( 1 )

    return SUCCESS;
} // End function int handlePackets()

int handleInboundPacket(int tunfd, int incoming_sockfd) 
{
    struct  tunhdr n_tun_hdr;
    int     bufSize;
    char    buffer[get_mtu()];

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

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, buffer, sizeof(struct tunhdr));

    // Copy temporary to host format
    unsigned int h_seq_no = ntohl(n_tun_hdr.seq);
    
    if(addSeqNum(packet_buffer, h_seq_no) == NOT_ADDED) {
        return SUCCESS;
    }

    unsigned short h_link_id = ntohs(n_tun_hdr.link_id);

    obtain_read_lock(&interface_list_lock);
    struct interface* ife = find_interface_by_index(interface_list, h_link_id);
    release_read_lock(&interface_list_lock);
    if(ife) {

        //unsigned short h_local_seq_no = ntohs(n_tun_hdr.local_seq_no);
    
        //unsigned short lost = h_local_seq_no - ife->local_seq_no_in;
        //if(lost > MAX_PACKET_LOSS) {
        //    ife->out_of_order_packets++;
        //} else {
        //    ife->packets_lost += lost;
        //    ife->local_seq_no_in = h_local_seq_no + 1;
        //}
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
    

    DEBUG_MSG("Writing data");
    if( write(tunfd, &buffer[sizeof(struct tunhdr)-TUNTAP_OFFSET], 
                    (bufSize-sizeof(struct tunhdr)+TUNTAP_OFFSET)) < 0) 
    {
        ERROR_MSG("write() failed");
        return FAILURE;
    }


    return SUCCESS;
} // End function int handleInboundPacket()

int handleOutboundPacket(int tunfd, struct tunnel * tun) 
{
    int bufSize;
    char buffer[get_mtu()];

    if( (bufSize = read(tunfd, buffer, get_mtu())) < 0) 
    {
        ERROR_MSG("read packet failed");
    } 
    else 
    {

        struct flow_tuple *ft = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
        struct iphdr    *ip_hdr = (struct iphdr *)(buffer + TUNTAP_OFFSET);
        struct tcphdr   *tcp_hdr = (struct tcphdr *)(buffer + TUNTAP_OFFSET + (ip_hdr->ihl * 4));

        // Policy and Flow table
        fill_flow_tuple(ip_hdr, tcp_hdr, ft);

        struct flow_entry *ftd = get_flow_entry(ft);
        if(ftd == NULL) {
            struct policy_entry *pd = malloc(sizeof(struct policy_entry));
            getMatch(ft, pd, EGRESS);
            update_flow_table(ft,pd->action, pd->type, pd->alg_name);
            free(pd);
            ftd = get_flow_entry(ft);
        }

        free(ft);

        // Check for drop
        if((ftd->action & POLICY_ACT_DROP) != 0) {
            return SUCCESS;
        }

        // Send on all interfaces
        if((ftd->action & POLICY_OP_DUPLICATE) != 0) {
            //sendAllInterfaces(buffer, bufSize);
            return SUCCESS;
        }

        // Select interface and send
        int rtn = 0;
        /*if(strcmp(ftd->alg_name, "rr_conn") == 0) {
            rtn = stripePacket(buffer, bufSize, RR_CONN);
        }
        else if(strcmp(ftd->alg_name, "rr_pkt") == 0) {
            rtn = stripePacket(buffer, bufSize, RR_PKT);
        }
        else if(strcmp(ftd->alg_name, "wrr_conn") == 0) {
            rtn = stripePacket(buffer, bufSize, WRR_CONN);
        }
        else if(strcmp(ftd->alg_name, "wrr_pkt") == 0) {
            rtn = stripePacket(buffer, bufSize, WRR_PKT);
        }
        else if(strcmp(ftd->alg_name, "wrr_pktv1") == 0) {
            rtn = stripePacket(buffer, bufSize, WRR_PKT_v1);
        }
        else if(strcmp(ftd->alg_name, "wdrr_pkt") == 0) {
            rtn = stripePacket(buffer, bufSize, WDRR_PKT);
        }
        else if(strcmp(ftd->alg_name, "spf") == 0) {
            rtn = stripePacket(buffer, bufSize, SPF);
        }
        else*/ {
            //rtn = stripePacket(buffer, bufSize, getRoutingAlgorithm());
        }
        
        if(rtn < 0) {
            ERROR_MSG("stripePacket() failed");
        }
    }

    return SUCCESS;
} // End function int handleOutboundPacket()