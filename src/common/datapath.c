#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/udp.h>

#include "configuration.h"
#include "constants.h"
#include "contchan.h"
#include "debug.h"
#include "datapath.h"
#include "flow_table.h"
#include "interface.h"
#include "headers.h"
#include "policy_table.h"
#include "packet_buffer.h"
#include "rwlock.h"
#include "rootchan.h"
#include "select_interface.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"
#include "packet.h"
#include "ping.h"
#include "rateinfer.h"
#include "remote_node.h"

#ifndef SIOCGSTAMP
# define SIOCGSTAMP 0x8906
#endif

int write_to_tunnel(int tunfd, char *packet, int size);
int handleInboundPacket(int tunfd, struct interface *ife);
int handleOutboundPacket(int tunfd, struct tunnel *tun);
int handlePackets();

static int                  running = 0;
static pthread_t            data_thread;
struct tunnel *             tun;
static unsigned int         tunnel_mtu = 0;
static unsigned int         outbound_mtu = 0;
static FILE *               packet_log_file;
static int                  packet_log_enabled = 0;
static char *               send_buffer;

int start_data_thread(struct tunnel *tun_in)
{
    //The mtu in the config file accounts for the tunhdr, but we have that extra space in here
    tunnel_mtu = get_mtu();
    outbound_mtu =  1500;
    send_buffer = (char *)malloc(sizeof(char)*1500);
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

static int nat_receive(int tunfd, int sockfd) {
    int     bufSize;
    char    buffer[outbound_mtu];

    struct sockaddr_storage     from;
    unsigned    fromlen = sizeof(from);

    bufSize = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
        (struct sockaddr *)&from, &fromlen);

    if(bufSize < 0) {
        ERROR_MSG("recvfrom() failed");
        return FAILURE;
    }


    struct iphdr * ip_hdr = (struct iphdr *)buffer;
    ip_hdr->daddr = tun->n_private_ip;
    compute_ip_checksum(ip_hdr);
    if(ip_hdr->protocol == 6) { 
        compute_tcp_checksum(&buffer[sizeof(struct iphdr)], bufSize - sizeof(struct iphdr), ip_hdr->saddr, ip_hdr->daddr);
    }

    struct flow_tuple ft;
    fill_flow_tuple(buffer, &ft, 1);

    struct flow_entry *fe = get_flow_entry(&ft);
    if(fe->ingress_action != POLICY_ACT_NAT) { return SUCCESS; }

    return write_to_tunnel(tunfd, buffer, bufSize);
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
            if(curr_ife->raw_icmp_sockfd > 0){
                FD_SET(curr_ife->raw_icmp_sockfd, &read_set);
            }
            if(curr_ife->raw_tcp_sockfd > 0){
                FD_SET(curr_ife->raw_tcp_sockfd, &read_set);
            }
            if(curr_ife->raw_udp_sockfd > 0){
                FD_SET(curr_ife->raw_udp_sockfd, &read_set);
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
            if( FD_ISSET(curr_ife->sockfd, &read_set) ) {
                handleInboundPacket(tun->tunnelfd, curr_ife);
            }
            if( FD_ISSET(curr_ife->raw_icmp_sockfd, &read_set) ) {
                nat_receive(tun->tunnelfd, curr_ife->raw_icmp_sockfd);
            }
            if( FD_ISSET(curr_ife->raw_tcp_sockfd, &read_set) ) {
                nat_receive(tun->tunnelfd, curr_ife->raw_tcp_sockfd);
            }
            if( FD_ISSET(curr_ife->raw_udp_sockfd, &read_set) ) {
                nat_receive(tun->tunnelfd, curr_ife->raw_udp_sockfd);
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

    unsigned int h_header_len = ntohs(((struct tunhdr *)buffer)->header_len);

    if(h_header_len == 0)
        h_header_len = sizeof(struct tunhdr);

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, buffer, h_header_len);

    // Copy temporary to host format
    unsigned int h_global_seq = ntohl(n_tun_hdr.global_seq);
    unsigned int h_link_seq = ntohl(n_tun_hdr.link_seq);
    unsigned int h_path_ack = ntohl(n_tun_hdr.path_ack);
    unsigned int h_remote_ts = ntohl(n_tun_hdr.remote_ts);
    unsigned int h_local_ts = ntohl(n_tun_hdr.local_ts);

    //Remote_ts is the remote send time in our local clock domain
    uint32_t recv_ts = timeval_to_usec(&arrival_time);
    if(h_remote_ts != 0) {
        long diff = (long)recv_ts - (long)h_remote_ts;

        ife->avg_rtt = ewma_update(ife->avg_rtt, (double)diff, RTT_EWMA_WEIGHT);
    }

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
        return send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, 1, ife, &from);
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
        return send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, 1, ife, &from);
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

    DEBUG_MSG("Receive: %s,%u,%u,%u,%u",
            update_ife->name,
            recv_ts,
            h_local_ts,
            h_link_seq,
            bufSize);

    update_burst(&update_ife->burst, recv_ts, h_local_ts, h_link_seq, bufSize);
    
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
    send_encap_packet_ife(TUNTYPE_ACK, "", 0, get_unique_id(), ife, remote_ife, &h_local_ts);
    if((n_tun_hdr.type == TUNTYPE_ACKREQ)){
        return SUCCESS;
    }

    if(packet_log_enabled && packet_log_file != NULL)
    {
        logPacket(&arrival_time, bufSize, "INGRESS", ife, remote_ife);
    }

    struct flow_tuple ft;
    // Policy and Flow table
    fill_flow_tuple(&buffer[h_header_len], &ft, 1);
    struct flow_entry *ftd = get_flow_entry(&ft);

    ftd->remote_node_id = node_id;
    ftd->remote_link_id = link_id;
    ftd->local_link_id = ife->index;

    update_flow_entry(ftd);

    return write_to_tunnel(tunfd, &buffer[h_header_len], bufSize - h_header_len);
    
} // End function int handleInboundPacket()

int write_to_tunnel(int tunfd, char *packet, int size) {
    
    if(size + TUNTAP_OFFSET > outbound_mtu) { 
        DEBUG_MSG("Tried to send packet larger than our send buffer %d", size);
        return FAILURE;
    }
    
    // This is needed to notify tun0 we are passing an IP packet
    // Have to pass in the IP proto as last two bytes in ethernet header
    //
    // Copy in four bytes, these four bytes represent the four bytes of the 
    // tunnel header (added by the tun device) this field is in network order.
    // In host order it would be 0x00000800 the first two bytes (0000) are
    // the flags field, the next two byte (0800 are the protocol field, in this
    // case IP): http://www.mjmwired.net/kernel/Documentation/networking/tuntap.txt

    struct iphdr *ip_hdr = (struct iphdr *)(packet);
    unsigned short tun_info[2];
    tun_info[0] = 0; //flags
    tun_info[1] = ip_hdr->version == 6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);
    memcpy(send_buffer, tun_info, TUNTAP_OFFSET);


    memcpy( (char *)&send_buffer[TUNTAP_OFFSET], packet, size);

    if( write(tunfd, send_buffer, size + TUNTAP_OFFSET) < 0)
    {
        ERROR_MSG("write() failed");
        return FAILURE;
    }

    return SUCCESS;
}

int handleOutboundPacket(int tunfd, struct tunnel * tun) 
{
    int ret = SUCCESS;

    //Leave room for the TUNTAP header
    struct packet *pkt = alloc_packet(0, tunnel_mtu + TUNTAP_OFFSET);
    
    int read_size = read(tunfd, pkt->data, pkt->tail_size);
    if (read_size >= 0) {
        packet_put(pkt, read_size);

        //Ignore the tuntap header
        packet_pull(pkt, TUNTAP_OFFSET);

        obtain_read_lock(&interface_list_lock);
        int output = queue_send_packet(pkt);
        release_read_lock(&interface_list_lock);

        ret = output;
    } else {
        ERROR_MSG("read packet failed");
    }

    free_packet(pkt);

    return ret;
} // End function int handleOutboundPacket()

int queue_send_packet(struct packet *pkt)
{
    return send_packet(pkt->data, pkt->data_size);
}

int send_packet(char *orig_packet, int orig_size)
{
    struct flow_tuple ft;

    // Policy and Flow table
    fill_flow_tuple(orig_packet, &ft, 0);

    struct flow_entry *ftd = get_flow_entry(&ft);

    update_flow_entry(ftd);

    // Check for drop
    if((ftd->egress_action & POLICY_ACT_MASK) == POLICY_ACT_DROP) {
        return SUCCESS;
    }

    // Send on all interfaces
    if((ftd->egress_action & POLICY_OP_DUPLICATE) != 0) {
        //sendAllInterfaces(orig_packet, orig_size);
        return SUCCESS;
    }
    //Add a tunnel header to the packet
    if((ftd->egress_action & POLICY_ACT_MASK) == POLICY_ACT_ENCAP) {
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
        return send_encap_packet_ife(TUNTYPE_DATA, orig_packet, orig_size, node_id, src_ife, dst_ife, NULL);
    }

    if((ftd->egress_action & POLICY_ACT_MASK) == POLICY_ACT_NAT) {
        struct interface *src_ife = select_src_interface(ftd);
        if(src_ife != NULL) {
            return send_nat_packet(orig_packet, orig_size, src_ife);
        }
    }

    return FAILURE;
}

int send_encap_packet_ife(uint8_t type, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife, uint32_t *remote_ts)
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
    return send_encap_packet_dst(type, packet, size, src_ife, &dst, update_ife, &remote_node->global_seq, remote_ts);
}

int send_encap_packet_dst_noinfo(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst)
{
    return send_encap_packet_dst(type, packet, size, src_ife, dst, NULL, NULL, NULL);
}
int send_encap_packet_dst(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst, struct interface *update_ife, uint32_t *global_seq, uint32_t *remote_ts)
{
    int output = FAILURE;
    char new_packet[size + sizeof(struct tunhdr)];
    memset(new_packet, 0, sizeof(new_packet));
    int new_size = add_tunnel_header(type, packet, size, new_packet, src_ife, update_ife, global_seq, remote_ts);
    output = send_ife_packet(new_packet, new_size, update_ife, src_ife->sockfd, (struct sockaddr *)dst);
    if(output == FAILURE) { return FAILURE; }
    src_ife->packets_since_ack++;
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
    return SUCCESS;
}

int send_nat_packet(char *orig_packet, int orig_size, struct interface *src_ife) {
    int sockfd = 0;
    int proto = ((struct iphdr*)orig_packet)->protocol;

    //Don't send the IP header, the kernel will take care of this
    char * new_packet = &orig_packet[sizeof(struct iphdr)];
    int new_size = orig_size - sizeof(struct iphdr);

    if(proto == 1)
        sockfd = src_ife->raw_icmp_sockfd;
    else if(proto == 6) {
        sockfd = src_ife->raw_tcp_sockfd;
        compute_tcp_checksum(new_packet, new_size, src_ife->public_ip.s_addr, ((struct iphdr*)orig_packet)->daddr);

    }
    else if(proto == 17) {
        sockfd = src_ife->raw_udp_sockfd;
        ((struct udphdr *)new_packet)->check = 0;
    }

    //Determine the destination
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(struct sockaddr_in));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ((struct iphdr*)orig_packet)->daddr;

    return send_ife_packet(new_packet, new_size, src_ife, sockfd, (struct sockaddr *)&dst);
}

int send_ife_packet(char *packet, int size, struct interface *ife, int sockfd, struct sockaddr * dst)
{
    if(sockfd == 0) {
        if(ife != NULL)
            DEBUG_MSG("Tried to send packet over bad sockfd on interface %s", ife->name);
        return FAILURE;
    }
    if((sendto(sockfd, packet, size, 0, (struct sockaddr *)dst, sizeof(struct sockaddr))) < 0)
    {
        if(ife != NULL)
            ERROR_MSG("sendto failed fd %d (%s),  dst: %s, new_size: %d", sockfd, ife->name, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), size);

        return FAILURE;
    }
    if(ife != NULL)
        ife->tx_bytes += size;
    return SUCCESS;
}
