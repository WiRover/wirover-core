#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include "configuration.h"
#include "debug.h"
#include "datapath.h"
#include "flow_table.h"
#include "interface.h"
#include "policyTable.h"
#include "packetBuffer.h"
#include "netlink.h"
#include "rwlock.h"
#include "rootchan.h"
#include "select_interface.h"
#include "sockets.h"
#include "tunnel.h"
#include "ping.h"
#include "remote_node.h"

#ifndef SIOCGSTAMP
# define SIOCGSTAMP 0x8906
#endif


static struct buffer_storage *packet_buffer[PACKET_BUFFER_SIZE];

int handleInboundPacket(int tunfd, struct interface *ife);
int handleOutboundPacket(int tunfd, struct tunnel *tun);
int handlePackets();

static int                  running = 0;
static pthread_t            data_thread;
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

    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result = pthread_create(&data_thread, &attr, (void *(*)(void *))handlePackets, NULL);
    if(result != 0) {
        ERROR_MSG("Creating thread failed");
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
        FD_SET(tun->tunnelfd, &read_set);
        obtain_read_lock(&interface_list_lock);
        struct interface* curr_ife = interface_list;
        while (curr_ife) {
            if(curr_ife->sockfd > 0){
                FD_SET(curr_ife->sockfd, &read_set);
            }
            curr_ife = curr_ife->next;
        }
        release_read_lock(&interface_list_lock);
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

        obtain_read_lock(&interface_list_lock);
        curr_ife = interface_list;
        while (curr_ife) {
            if( FD_ISSET(curr_ife->sockfd, &read_set) ) 
            {
                handleInboundPacket(tun->tunnelfd, curr_ife);
            }
            curr_ife = curr_ife->next;
        }
        release_read_lock(&interface_list_lock);

        if( FD_ISSET(tun->tunnelfd, &read_set) ) 
        {
            handleOutboundPacket(tun->tunnelfd, tun);
        }

    } // while( 1 )

    return SUCCESS;
} // End function int handlePackets()

int handleInboundPacket(int tunfd, struct interface *ife) 
{
    struct  tunhdr n_tun_hdr;
    int     bufSize;
    char    buffer[outbound_mtu];

    struct sockaddr_storage     from;
    unsigned    fromlen = sizeof(from);

    bufSize = recvfrom(ife->sockfd, buffer, sizeof(buffer), 0, 
        (struct sockaddr *)&from, &fromlen);
    if(bufSize < 0) {
        ERROR_MSG("recvfrom() failed");
        return FAILURE;
    }

    

    struct timeval arrival_time;
    if(ioctl(ife->sockfd, SIOCGSTAMP, &arrival_time) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&arrival_time, 0);
    }
    ife->rx_time = arrival_time.tv_sec * USEC_PER_SEC + arrival_time.tv_usec;
    ife->packets_since_ack = 0;
    ife->stall_waiting = 0;
    change_interface_state(ife, ACTIVE);

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, buffer, sizeof(struct tunhdr));

    // Copy temporary to host format
    unsigned int h_seq_no = ntohl(n_tun_hdr.seq);
    uint16_t node_id = ntohs(n_tun_hdr.node_id);
    uint16_t link_id = ntohs(n_tun_hdr.link_id);
    struct interface *remote_ife = NULL;

    struct remote_node *gw = lookup_remote_node_by_id(node_id);
    if(gw != NULL)
        remote_ife = find_interface_by_index(gw->head_interface, link_id);

    //An ack is an empty packet meant only to update our interface's tx_ack
    if((n_tun_hdr.flags & TUNFLAG_ACK) != 0) {
        return SUCCESS;
    }
    //Process the ping even though we may not have an entry in our remote_nodes
    if((n_tun_hdr.flags & TUNFLAG_PING) != 0){
        handle_incoming_ping(&from, arrival_time, ife, remote_ife, &buffer[sizeof(struct tunhdr)], bufSize - sizeof(struct tunhdr));
        return SUCCESS;
    }

    //If it's not a ping and we don't have an entry, it's an error
    if(remote_ife == NULL) { 
        DEBUG_MSG("Received packet from unknown node %d link %d", node_id, link_id);
        return FAILURE;
    }

    //Send an ack
    send_packet(TUNFLAG_ACK, "", 0, get_unique_id(), ife, remote_ife);

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

    ftd->remote_node_id = node_id;
    ftd->remote_link_id = link_id;
    ftd->local_link_id = ife->index;

    update_flow_entry(ftd);


    unsigned short tun_info[2];
    tun_info[0] = 0; //flags
    tun_info[1] = ip_hdr->version == 6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);
    memcpy(&buffer[sizeof(struct tunhdr) - TUNTAP_OFFSET], tun_info, TUNTAP_OFFSET);

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
    //Leave room for the TUNTAP header
    char *orig_packet;
    char buffer[tunnel_mtu + TUNTAP_OFFSET];
    if( (orig_size = read(tunfd, buffer, sizeof(buffer))) < 0) 
    {
        ERROR_MSG("read packet failed");
    } 
    else 
    {
        //Ignore the tuntap header
        orig_packet = &buffer[TUNTAP_OFFSET];
        orig_size -= TUNTAP_OFFSET;

        struct flow_tuple ft;
        struct iphdr    *ip_hdr = (struct iphdr *)(orig_packet);
        struct tcphdr   *tcp_hdr = (struct tcphdr *)(orig_packet + (ip_hdr->ihl * 4));

        // Policy and Flow table
        fill_flow_tuple(ip_hdr, tcp_hdr, &ft, 0);

        struct flow_entry *ftd = get_flow_entry(&ft);

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
            int node_id = get_unique_id();

            obtain_read_lock(&interface_list_lock);

            struct interface *src_ife = select_src_interface(ftd);
            if(src_ife != NULL) {
                ftd->local_link_id = src_ife->index;
            }

            struct interface *dst_ife = select_dst_interface(ftd);
            if(dst_ife != NULL) { 
                ftd->remote_link_id = dst_ife->index;
                ftd->remote_node_id = dst_ife->node_id;
            }

            release_read_lock(&interface_list_lock);

            return send_packet(TUNFLAG_DATA, orig_packet, orig_size, node_id, src_ife, dst_ife);
        }
    }

    return SUCCESS;
} // End function int handleOutboundPacket()

int send_packet(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife)
{
    if(dst_ife == NULL || src_ife == NULL)
    {
        DEBUG_MSG("Tried to send packet to null interface");
        return FAILURE;
    }
    struct sockaddr_storage dst;
    build_data_sockaddr(dst_ife, &dst);
    return send_sock_packet(flags, packet, size, node_id, src_ife, &dst);
}

int send_sock_packet(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct sockaddr_storage *dst)
{
    int sockfd = src_ife->sockfd;
    int rtn = 0;
    if ( sockfd == 0 )
    {
        DEBUG_MSG("Tried to send packet over bad sockfd for interface %d", src_ife->name);
        return FAILURE;
    }
    char *new_packet = (char *)malloc(size + sizeof(struct tunhdr));
    int new_size = add_tunnel_header(flags, packet, size, new_packet, node_id, src_ife);

    if( (rtn = sendto(sockfd, new_packet, new_size, 0, (struct sockaddr *)dst, sizeof(struct sockaddr))) < 0)
    {
        ERROR_MSG("sendto failed (%d), fd %d,  dst: %s, new_size: %d", rtn, sockfd, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), new_size);

        return FAILURE;
    }
    src_ife->packets_since_ack++;
    if(src_ife->packets_since_ack > 5) { 
        src_ife->stall_waiting = 1;
        change_interface_state(src_ife, INACTIVE);
    }
    free(new_packet);
    return SUCCESS;
}