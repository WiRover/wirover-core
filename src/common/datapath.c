#include <arpa/inet.h>
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
#include "rootchan.h"
#include "selectInterface.h"
#include "sockets.h"
#include "tunnel.h"
#include "ping.h"
#ifdef CONTROLLER
#include "gateway.h"
#endif

#ifndef SIOCGSTAMP
# define SIOCGSTAMP 0x8906
#endif


static struct buffer_storage *packet_buffer[PACKET_BUFFER_SIZE];

int handleInboundPacket(int tunfd, int data_socket);
int handleOutboundPacket(int tunfd, struct tunnel *tun);
int handlePackets();

static int                  running = 0;
static pthread_t            data_thread;
static int                  data_socket = -1;
struct tunnel *tun;
static unsigned int         tunnel_mtu = 0;
static unsigned int         outbound_mtu = 0;

int start_data_thread(struct tunnel *tun_in)
{
    //The mtu in the config file accounts for the tunhdr, but we have that extra space in here
    tunnel_mtu = get_mtu();
    outbound_mtu =  1500;
    tun = tun_in;
    if(running) {
        DEBUG_MSG("Data thread already running");
        return SUCCESS;
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

    int result = pthread_create(&data_thread, &attr, (void *(*)(void *))handlePackets, NULL);
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
    fd_set read_set;
    sigset_t orig_set;

    initPacketBuffer(packet_buffer);


    while( 1 )
    {
        FD_ZERO(&read_set);
        FD_SET(data_socket, &read_set);
        FD_SET(tun->tunnelfd, &read_set);
#ifdef GATEWAY        
        obtain_read_lock(&interface_list_lock);
        struct interface* curr_ife = interface_list;
        while (curr_ife) {
            if(curr_ife->sockfd > 0){
                FD_SET(curr_ife->sockfd, &read_set);
            }
            curr_ife = curr_ife->next;
        }
        release_read_lock(&interface_list_lock);
#endif
        // Pselect should return
        // when SIGINT, or SIGTERM is delivered, but block SIGALRM
        sigemptyset(&orig_set);
        sigaddset(&orig_set, SIGALRM);

        int rtn = pselect(FD_SETSIZE, &read_set, NULL, NULL, NULL, &orig_set);
        // Make sure select didn't fail
        if( rtn < 0 && errno == EINTR) 
        {
            DEBUG_MSG("select() failed");
            continue;
        }

        if( FD_ISSET(data_socket, &read_set) ) 
        {
            handleInboundPacket(tun->tunnelfd, data_socket);
        }
#ifdef GATEWAY        
        obtain_read_lock(&interface_list_lock);
        curr_ife = interface_list;
        while (curr_ife) {
            if( FD_ISSET(curr_ife->sockfd, &read_set) ) 
            {
                handleInboundPacket(tun->tunnelfd, curr_ife->sockfd);
            }
            curr_ife = curr_ife->next;
        }
        release_read_lock(&interface_list_lock);
#endif
        if( FD_ISSET(tun->tunnelfd, &read_set) ) 
        {
            handleOutboundPacket(tun->tunnelfd, tun);
        }

    } // while( 1 )

    return SUCCESS;
} // End function int handlePackets()

int handleInboundPacket(int tunfd, int data_socket) 
{
    struct  tunhdr n_tun_hdr;
    int     bufSize;
    char    buffer[outbound_mtu];

    struct sockaddr_storage     from;
    unsigned    fromlen = sizeof(from);

    bufSize = recvfrom(data_socket, buffer, sizeof(buffer), 0, 
        (struct sockaddr *)&from, &fromlen);
    if(bufSize < 0) {
        ERROR_MSG("recvfrom() failed");
        return FAILURE;
    }

    

    struct timeval arrival_time;
    if(ioctl(data_socket, SIOCGSTAMP, &arrival_time) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&arrival_time, 0);
    }

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, buffer, sizeof(struct tunhdr));

    // Copy temporary to host format
    unsigned int h_seq_no = ntohl(n_tun_hdr.seq);
    uint16_t node_id = ntohs(n_tun_hdr.node_id);
    uint16_t link_id = ntohs(n_tun_hdr.link_id);
    //DEBUG_MSG("Tunflags %x, ping flag %x anded %x", n_tun_hdr.flags, TUNFLAG_PING);
    if((n_tun_hdr.flags & TUNFLAG_PING) != 0){
        handle_incoming_ping(&from, arrival_time, data_socket, &buffer[sizeof(struct tunhdr)], bufSize - sizeof(struct tunhdr));
        return SUCCESS;
    }

    DEBUG_MSG("Received node_id: %d, linkid: %d",node_id, link_id);
    if(addSeqNum(packet_buffer, h_seq_no) == NOT_ADDED) {
        return SUCCESS;
    }

    // This is needed to notify tun0 we are passing an IP packet
    // Have to pass in the IP proto as last two bytes in ethernet header
    //
    // Copy in four bytes, these four bytes represent the four bytes of the 
    // tunnel header (added by the tun device) this field is in network order.
    // In host order it would be 0x00000800 the first two bytes (0000) are
    // the flags field, the next two byte (0800 are the protocol field, in this
    // case IP): http://www.mjmwired.net/kernel/Documentation/networking/tuntap.txt

    struct iphdr *ip_hdr = (struct iphdr *)(buffer + sizeof(struct tunhdr));

    struct flow_tuple *ft = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
    struct tcphdr   *tcp_hdr = (struct tcphdr *)(buffer + sizeof(struct tunhdr) + (ip_hdr->ihl * 4));

    // Policy and Flow table
    fill_flow_tuple(ip_hdr, tcp_hdr, ft, 1);
    struct flow_entry *ftd = get_flow_entry(ft);

#ifdef CONTROLLER
    update_flow_entry(ftd, node_id, link_id);
#endif


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
    int orig_size;
    char orig_packet[tunnel_mtu];

    if( (orig_size = read(tunfd, orig_packet, sizeof(orig_packet))) < 0) 
    {
        ERROR_MSG("read packet failed");
    } 
    else 
    {

        struct flow_tuple *ft = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
        struct iphdr    *ip_hdr = (struct iphdr *)(orig_packet + TUNTAP_OFFSET);
        struct tcphdr   *tcp_hdr = (struct tcphdr *)(orig_packet + TUNTAP_OFFSET + (ip_hdr->ihl * 4));

        // Policy and Flow table
        fill_flow_tuple(ip_hdr, tcp_hdr, ft, 0);

        struct flow_entry *ftd = get_flow_entry(ft);
        free(ft);

        // Check for drop
        if((ftd->action & POLICY_ACT_MASK) == POLICY_ACT_DROP) {
            return SUCCESS;
        }

        // Send on all interfaces
        if((ftd->action & POLICY_OP_DUPLICATE) != 0) {
            //sendAllInterfaces(orig_packet, orig_size);
            return SUCCESS;
        }
        //Add a tunnel header to the packet
        if((ftd->action & POLICY_ACT_MASK) == POLICY_ACT_ENCAP) {
            int node_id;
            int link_id;
            int sockfd;
            struct interface *dst_ife;
#ifdef CONTROLLER
            link_id = ftd->link_id;
            node_id = ftd->node_id;
            struct gateway *gw;
            gw = lookup_gateway_by_id(node_id);
            if(gw == NULL) {
                DEBUG_MSG("Dropping packet destined for unknown gateway");
                print_flow_table();
                return SUCCESS;
            }
            DEBUG_MSG("Oubtound packet for link %d", link_id);
            dst_ife = find_interface_by_index(gw->head_interface, link_id);
            sockfd = data_socket;
#endif
#ifdef GATEWAY
            dst_ife = get_controller_ife();
            node_id = get_unique_id();

            obtain_read_lock(&interface_list_lock);
            struct interface *src_ife = interface_list;
            link_id = src_ife->index;
            sockfd = src_ife->sockfd;
            update_flow_entry(ftd, node_id, link_id);
            release_read_lock(&interface_list_lock);

#endif
            struct sockaddr_storage dst;
            build_data_sockaddr(dst_ife, &dst);
            return sendPacket(TUNFLAG_DATA, &orig_packet[TUNTAP_OFFSET], orig_size - TUNTAP_OFFSET, node_id, link_id, sockfd, &dst, 0);
        }
    }

    return SUCCESS;
} // End function int handleOutboundPacket()