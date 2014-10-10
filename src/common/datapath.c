#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include "configuration.h"
#include "constants.h"
#include "contchan.h"
#include "debug.h"
#include "datapath.h"
#include "flow_table.h"
#include "interface.h"
#include "policy_table.h"
#include "packet_buffer.h"
#include "netlink.h"
#include "rwlock.h"
#include "rootchan.h"
#include "select_interface.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"
#include "ping.h"
#include "remote_node.h"

#ifndef SIOCGSTAMP
# define SIOCGSTAMP 0x8906
#endif

int handleInboundPacket(int tunfd, struct interface *ife);
int handleOutboundPacket(int tunfd, struct tunnel *tun);
int handlePackets();

static int                  running = 0;
static pthread_t            data_thread;
struct tunnel *tun;
static unsigned int         tunnel_mtu = 0;
static unsigned int         outbound_mtu = 0;
static FILE *               packet_log_file;
static int                  packet_log_enabled = 0;

int start_data_thread(struct tunnel *tun_in)
{
    //The mtu in the config file accounts for the tunhdr, but we have that extra space in here
    tunnel_mtu = get_mtu();
    outbound_mtu =  1500;
    tun = tun_in;
    if(get_packet_log_enabled()){
        packet_log_file = fopen(get_packet_log_path(), "a");
        if(packet_log_file == NULL) {
            ERROR_MSG("Failed to open packet log file for writing %s", get_packet_log_path());
        }
        else{
            packet_log_enabled = 1;
        }
    }
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
void logPacket(struct timeval *arrival_time, int size, const char *direction, struct interface *local_ife, struct interface *remote_ife)
{
    fprintf(packet_log_file, "%ld.%06ld, %s, %s, %d, %d, %s\n",arrival_time->tv_sec, arrival_time->tv_usec,
        local_ife->name, remote_ife->name, remote_ife->node_id, size, direction);
    fflush(packet_log_file);
}
int handlePackets()
{
    // The File Descriptor set to add sockets to
    fd_set read_set;
    sigset_t orig_set;
    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 100 * NSECS_PER_MSEC;

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

        int rtn = pselect(FD_SETSIZE, &read_set, NULL, NULL, &timeout, &orig_set);
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

    ife->rx_bytes += bufSize;

    struct timeval arrival_time;
    if(ioctl(ife->sockfd, SIOCGSTAMP, &arrival_time) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&arrival_time, 0);
    }

    ife->rx_time = arrival_time;
    ife->packets_since_ack = 0;
    change_interface_state(ife, ACTIVE);

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, buffer, sizeof(struct tunhdr));

    // Copy temporary to host format
    unsigned int h_global_seq = ntohl(n_tun_hdr.global_seq);
    unsigned int h_link_seq = ntohl(n_tun_hdr.link_seq);
    unsigned int h_path_ack = ntohl(n_tun_hdr.path_ack);
    unsigned int h_header_len = ntohs(n_tun_hdr.header_len);

    if(h_header_len == 0)
        h_header_len = sizeof(struct tunhdr);

    uint16_t node_id = ntohs(n_tun_hdr.node_id);
    uint16_t link_id = ntohs(n_tun_hdr.link_id);
    struct interface *remote_ife = NULL;

    if(n_tun_hdr.type == TUNTYPE_ERROR){
#ifdef GATEWAY
        send_notification(1);
#endif
        return SUCCESS;
    }

    struct remote_node *gw = lookup_remote_node_by_id(node_id);
    if(gw == NULL)
    {
        DEBUG_MSG("Sending error for bad node");
        char error[] = { TUNERROR_BAD_NODE };
        return send_sock_packet(TUNTYPE_ERROR, error, 1, ife, &from, NULL, NULL);
    }
    
    if(pb_add_seq_num(gw->rec_seq_buffer, h_global_seq) == DUPLICATE) {
        //TODO: This doesn't quite work yet, when a controller or gateway get out of sync
        //this method will drop all packets because the sequence numbers start over
        //return SUCCESS;
    }

    remote_ife = find_interface_by_index(gw->head_interface, link_id);
    if(remote_ife == NULL)
    {
        DEBUG_MSG("Sending error for bad link %d", link_id);
        char error[] = { TUNERROR_BAD_LINK };
        return send_sock_packet(TUNTYPE_ERROR, error, 1, ife, &from, NULL, NULL);
    }

    struct interface *update_ife;
#ifdef CONTROLLER
    update_ife = remote_ife;
#endif
#ifdef GATEWAY
    update_ife = ife;
#endif

    update_ife->remote_ack = h_path_ack;
    update_ife->remote_seq = h_link_seq;

    obtain_write_lock(&update_ife->rt_buffer.rwlock);
    pb_free_packets(&update_ife->rt_buffer, h_path_ack);
    release_write_lock(&update_ife->rt_buffer.rwlock);

    //An ack is an empty packet meant only to update our interface's rx_time and packets_since_ack
    if((n_tun_hdr.type == TUNTYPE_ACK)) {
        return SUCCESS;
    }
    //Process the ping even though we may not have an entry in our remote_nodes
    if((n_tun_hdr.type == TUNTYPE_PING)){
        handle_incoming_ping(&from, arrival_time, ife, remote_ife, &buffer[h_header_len], bufSize - h_header_len);
        return SUCCESS;
    }

    //If it's not a ping and we don't have an entry, it's an error
    if(remote_ife == NULL) { 
        DEBUG_MSG("Received packet from unknown node %d link %d", node_id, link_id);
        return FAILURE;
    }

    //Send an ack and return if the packet was only requesting an ack
    send_ife_packet(TUNTYPE_ACK, "", 0, get_unique_id(), ife, remote_ife);
    if((n_tun_hdr.type == TUNTYPE_ACKREQ)){
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

    struct iphdr *ip_hdr = (struct iphdr *)(buffer + h_header_len);

    struct flow_tuple *ft = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
    struct tcphdr   *tcp_hdr = (struct tcphdr *)(buffer + h_header_len + (ip_hdr->ihl * 4));

    if(packet_log_enabled && packet_log_file != NULL)
    {
        logPacket(&arrival_time, bufSize, "INGRESS", ife, remote_ife);
    }

    // Policy and Flow table
    fill_flow_tuple(ip_hdr, tcp_hdr, ft, 1);
    struct flow_entry *ftd = get_flow_entry(ft);
    free(ft);

    ftd->remote_node_id = node_id;
    ftd->remote_link_id = link_id;
    ftd->local_link_id = ife->index;

    update_flow_entry(ftd);

    unsigned short tun_info[2];
    tun_info[0] = 0; //flags
    tun_info[1] = ip_hdr->version == 6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);
    memcpy(&buffer[h_header_len - TUNTAP_OFFSET], tun_info, TUNTAP_OFFSET);

    if( write(tunfd, &buffer[h_header_len - TUNTAP_OFFSET], 
        (bufSize - h_header_len + TUNTAP_OFFSET)) < 0)
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
        obtain_read_lock(&interface_list_lock);
        int output = send_packet(orig_packet, orig_size);
        release_read_lock(&interface_list_lock);

        return output;
    }

    return SUCCESS;
} // End function int handleOutboundPacket()

int send_packet(char *orig_packet, int orig_size)
{
    struct flow_tuple ft;
    struct iphdr    *ip_hdr = (struct iphdr *)(orig_packet);
    struct tcphdr   *tcp_hdr = (struct tcphdr *)(orig_packet + (ip_hdr->ihl * 4));

    // Policy and Flow table
    fill_flow_tuple(ip_hdr, tcp_hdr, &ft, 0);

    struct flow_entry *ftd = get_flow_entry(&ft);

    update_flow_entry(ftd);

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
        struct interface *src_ife = select_src_interface(ftd);
        if(src_ife != NULL) {
            ftd->local_link_id = src_ife->index;
        }

        struct interface *dst_ife = select_dst_interface(ftd);
        if(dst_ife != NULL) {
            ftd->remote_link_id = dst_ife->index;
            ftd->remote_node_id = dst_ife->node_id;
        }
        return send_ife_packet(TUNTYPE_DATA, orig_packet, orig_size, node_id, src_ife, dst_ife);
    }
    return SUCCESS;
}

int send_ife_packet(uint8_t type, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife)
{
    if(dst_ife == NULL || src_ife == NULL)
    {
        return FAILURE;
    }
    
    if(type == TUNTYPE_DATA && packet_log_enabled && packet_log_file != NULL){
        struct timeval tv;
        gettimeofday(&tv, 0);
        logPacket(&tv, size, "EGRESS", src_ife, dst_ife);
    }
    struct sockaddr_storage dst;
    build_data_sockaddr(dst_ife, &dst);
    struct remote_node *remote_node = lookup_remote_node_by_id(dst_ife->node_id);
    if(remote_node == NULL) {
        DEBUG_MSG("Destination interface %s had bad remote_node id %d", dst_ife->name, dst_ife->node_id);
        return FAILURE;
    }
    struct interface *update_ife;
#ifdef CONTROLLER
    update_ife = dst_ife;
#endif
#ifdef GATEWAY
    update_ife = src_ife;
#endif

    //There is a a possible infinite loop where send packet
    if(update_ife->state == ACTIVE) {
        obtain_write_lock(&update_ife->rt_buffer.rwlock);
        pb_add_packet(&update_ife->rt_buffer, update_ife->local_seq, packet, size);
        release_write_lock(&update_ife->rt_buffer.rwlock);
    }
    return send_sock_packet(type, packet, size, src_ife, &dst, update_ife, &remote_node->global_seq);
}

int send_sock_packet(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst, struct interface *update_ife, uint32_t *global_seq)
{
    int sockfd = src_ife->sockfd;
    int rtn = 0;
    if ( sockfd == 0 )
    {
        DEBUG_MSG("Tried to send packet over bad sockfd for interface %d", src_ife->name);
        return FAILURE;
    }
    char *new_packet = (char *)malloc(size + sizeof(struct tunhdr));
    int new_size = add_tunnel_header(type, packet, size, new_packet, src_ife, update_ife, global_seq);

    if( (rtn = sendto(sockfd, new_packet, new_size, 0, (struct sockaddr *)dst, sizeof(struct sockaddr))) < 0)
    {
        ERROR_MSG("sendto failed (%d), fd %d (%s),  dst: %s, new_size: %d", rtn, sockfd, src_ife->name, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), new_size);

        return FAILURE;
    }
    src_ife->packets_since_ack++;
    src_ife->tx_bytes += new_size;
#ifdef GATEWAY
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if(src_ife->packets_since_ack == 3)
    {
        src_ife->st_time = tv;
    }
    if(src_ife->packets_since_ack >= 3 && timeval_diff(&tv, &src_ife->st_time) > (src_ife->avg_rtt + 100 * USECS_PER_MSEC) * 2){
        change_interface_state(src_ife, INACTIVE);
    }
#endif
    gettimeofday(&src_ife->tx_time, NULL);
    free(new_packet);
    return SUCCESS;
}