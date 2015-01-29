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
    #define SIOCGSTAMP 0x8906
#endif



int handle_packet(struct interface * ife, int sockfd, int is_nat);
int handle_ife_packet(struct packet *pkt, struct interface * ife, int is_nat);
int handle_nat_packet(struct packet *pkt, struct interface *ife);
int handle_encap_packet(struct packet *pkt, struct interface *ife, struct sockaddr_storage *from);
// Sends a packet over the tunnel specified, if a flow entry or interface
// is included, the packet may be queued if either are over their rate limit.
// The packet will not be queued if NULL is passed in for either parameter.
int handle_flow_packet(struct packet * pkt, struct flow_entry *fe, int allow_enqueue);
int handleInboundPacket(struct interface *ife);
int handleOutboundPacket(struct tunnel *tun);
int handlePackets();
int service_queues();

static int                  running = 0;
static pthread_t            data_thread;
struct tunnel *             tun;
static unsigned int         tunnel_mtu = 0;
static unsigned int         outbound_mtu = 0;
static FILE *               packet_log_file;
static int                  packet_log_enabled = 0;
static char *               send_buffer;
static struct packet *      tx_queue_head;
static struct packet *      tx_queue_tail;

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
}/*
* WAIT FOR DATAPATH THREAD
*/
int stop_datapath_thread()
{
    running = 0;
    return pthread_join(data_thread, 0);
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
    timeout.tv_nsec = 20 * NSECS_PER_MSEC;

    while( running )
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
        service_queues();

        obtain_read_lock(&interface_list_lock);
        curr_ife = interface_list;
        while (curr_ife) {
            if( FD_ISSET(curr_ife->sockfd, &read_set) ) {
                handle_packet(curr_ife, curr_ife->sockfd, 0);
            }
            if( FD_ISSET(curr_ife->raw_icmp_sockfd, &read_set) ) {
                handle_packet(curr_ife, curr_ife->raw_icmp_sockfd, 1);
            }
            if( FD_ISSET(curr_ife->raw_tcp_sockfd, &read_set) ) {
                handle_packet(curr_ife, curr_ife->raw_tcp_sockfd, 1);
            }
            if( FD_ISSET(curr_ife->raw_udp_sockfd, &read_set) ) {
                handle_packet(curr_ife, curr_ife->raw_udp_sockfd, 1);
            }
            curr_ife = curr_ife->next;
        }
        release_read_lock(&interface_list_lock);

        if( FD_ISSET(tun->tunnelfd, &read_set) ) 
        {
            handleOutboundPacket(tun);
        }

    } // while( 1 )

    return SUCCESS;
} // End function int handlePackets()

int handle_packet(struct interface * ife, int sockfd, int is_nat)
{
    int     received_bytes;
    struct packet * pkt = alloc_packet(0, outbound_mtu);

    struct sockaddr_storage     from;
    unsigned    fromlen = sizeof(from);

    received_bytes = recvfrom(sockfd, pkt->data, pkt->tail_size, 0, 
        (struct sockaddr *)&from, &fromlen);
    if(received_bytes < 0) {
        ERROR_MSG("recvfrom() failed");
        free_packet(pkt);
        return FAILURE;
    }

    packet_put(pkt, received_bytes);

    struct timeval arrival_time;
    if(ioctl(sockfd, SIOCGSTAMP, &arrival_time) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&arrival_time, 0);
    }
    pkt->created = arrival_time;

    if(is_nat)
    {
        return handle_nat_packet(pkt, ife);
    }
    else
    {
        ife->rx_time = arrival_time;
        ife->packets_since_ack = 0;
        change_interface_state(ife, ACTIVE);
        return handle_encap_packet(pkt, ife, &from);
    }
    return FAILURE;
}

int handle_encap_packet(struct packet * pkt, struct interface *ife, struct sockaddr_storage * from)
{
    struct  tunhdr n_tun_hdr;

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, pkt->data, sizeof(struct tunhdr));
    // Copy temporary to host format
    uint8_t tun_type = n_tun_hdr.type & TUNTYPE_TYPE_MASK;
    uint8_t tun_ctl = n_tun_hdr.type & TUNTYPE_CONTROL_MASK;
    unsigned int h_global_seq = ntohl(n_tun_hdr.global_seq);
    unsigned int h_link_seq = ntohl(n_tun_hdr.link_seq);
    unsigned int h_path_ack = ntohl(n_tun_hdr.path_ack);
    unsigned int h_remote_ts = ntohl(n_tun_hdr.remote_ts);
    unsigned int h_local_ts = ntohl(n_tun_hdr.local_ts);

    uint16_t node_id = ntohs(n_tun_hdr.node_id);
    uint16_t link_id = ntohs(n_tun_hdr.link_id);

    //Strip the tunnel header from our packet
    packet_pull(pkt, sizeof(struct tunhdr));

    struct remote_node *gw = lookup_remote_node_by_id(node_id);

    if(tun_type == TUNTYPE_ERROR){
        int error = pkt->data[0];
        DEBUG_MSG("Received an error: %d", error);

        // The sequence number buffer is invalid if the remote node has no record for us
        if(error == TUNERROR_BAD_NODE && gw != NULL) {
            pb_clear_buffer(gw->rec_seq_buffer);
#ifdef GATEWAY
            send_startup_notification();
#endif
        }
        else if(error == TUNERROR_BAD_LINK)
        {
#ifdef GATEWAY
            send_notification(1);
#endif
        }
        else if(error == TUNERROR_BAD_FLOW)
        {
            struct flow_tuple ft;
            ft = *(struct flow_tuple*)&pkt->data[1];
            flow_tuple_invert(&ft);
            struct flow_entry *fe = get_flow_entry(&ft);
            if(fe == NULL) {
                DEBUG_MSG("Received flow error for unknown flow");
            }
            else {
                fe->requires_flow_info++;
            }
        }
        free_packet(pkt);
        return SUCCESS;
    }

    //Remote_ts is the remote send time in our local clock domain
    uint32_t recv_ts = timeval_to_usec(&pkt->created);
    if(h_remote_ts != 0) {
        long diff = (long)recv_ts - (long)h_remote_ts;

        ife->avg_rtt = ewma_update(ife->avg_rtt, (double)diff, RTT_EWMA_WEIGHT);
    }
    if(pkt->data_size > 800 && h_local_ts != 0) {
        float *current = cbuffer_current(&ife->rtt_buffer);
        float diff = 1.0f * ((long)h_local_ts - (long)recv_ts);
        if(*current == 0 || diff < *current)
        {
            *current = diff;
        }
        float queing_delay = diff - cbuffer_min(&ife->rtt_buffer);
        if(queing_delay != 0) {
            ife->base_rtt_diff = ewma_update(ife->base_rtt_diff, (double)queing_delay, RTT_EWMA_WEIGHT);
        }
        if(ife->base_rtt_diff != 0) {
            ife->est_downlink_bw = ewma_update(ife->est_downlink_bw, (double)pkt->data_size / (ife->base_rtt_diff) * 8.0, BW_EWMA_WEIGHT);
        }
    }

    struct interface *remote_ife = NULL;

    if(gw == NULL)
    {
        DEBUG_MSG("Sending error for bad node");
        char error[] = { TUNERROR_BAD_NODE };
        free_packet(pkt);
        return send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, 1, ife, from);
    }

    remote_ife = find_interface_by_index(gw->head_interface, link_id);
    if(remote_ife == NULL)
    {
        DEBUG_MSG("Sending error for bad link %d", link_id);
        char error[] = { TUNERROR_BAD_LINK };
        free_packet(pkt);
        return send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, 1, ife, from);
    }

    // If the flow is data, make sure we have an entry for it in our
    // flow table
    if(tun_type == TUNTYPE_DATA)
    {
        struct flow_tuple ft;

        if(tun_ctl == TUNTYPE_FLOW_INFO)
        {
            ft = *(struct flow_tuple *)(pkt->data);
            packet_pull(pkt, sizeof(struct flow_tuple));
            struct tunhdr_flow_info * ingress_info = (struct tunhdr_flow_info *)pkt->data;
            packet_pull(pkt, sizeof(struct tunhdr_flow_info));
            struct tunhdr_flow_info * egress_info = (struct tunhdr_flow_info *)pkt->data;
            flow_tuple_invert(&ft);
            struct flow_entry * fe = add_entry(&ft, 0);
            fe->ingress.action = ingress_info->action;
            fe->ingress.remote_node_id = node_id;
            fe->ingress.remote_link_id = ingress_info->local_link_id;
            fe->ingress.local_link_id = ingress_info->remote_link_id;

            fe->egress.action = egress_info->action;
            fe->egress.remote_node_id = node_id;
            fe->egress.remote_link_id = egress_info->local_link_id;
            fe->egress.local_link_id = egress_info->remote_link_id;
            free_packet(pkt);
            return SUCCESS;
        }

        fill_flow_tuple(pkt->data, &ft, 1);

        struct flow_entry *fe = get_flow_entry(&ft);
        if(fe == NULL) {
            DEBUG_MSG("Bad flow");
            print_flow_tuple(&ft);
            free_packet(pkt);
            char error[sizeof(struct flow_tuple) + 1];
            error[0] = TUNERROR_BAD_FLOW;
            *(struct flow_tuple *)&error[1] = ft;
            return send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, sizeof(error), ife, from);
        }
        if(!fe->owner) {
            fe->ingress.remote_link_id = link_id;
            fe->ingress.remote_node_id = node_id;
            fe->ingress.local_link_id = ife->index;
        }
        fe->requires_flow_info = 0;
    }

    // Verify the packet isn't a duplicate. Even if it is, send an ack
    // so that the remote link won't stall
    if(pb_add_seq_num(gw->rec_seq_buffer, h_global_seq) == DUPLICATE) {
        send_encap_packet_ife(TUNTYPE_ACK, "", 0, get_unique_id(), ife, remote_ife, &h_local_ts, 0);
        return SUCCESS;
    }

    struct interface *update_ife;
    struct interface *head_ife;
#ifdef CONTROLLER
    update_ife = remote_ife;
    head_ife = gw->head_interface;
#endif
#ifdef GATEWAY
    update_ife = ife;
    head_ife = interface_list;
#endif

    while(head_ife){
        obtain_write_lock(&head_ife->rt_buffer.rwlock);
        pb_free_packets(&head_ife->rt_buffer, h_path_ack);   
        release_write_lock(&head_ife->rt_buffer.rwlock);
        head_ife = head_ife->next;
    }

    update_ife->remote_ack = h_path_ack;
    update_ife->remote_seq = h_link_seq;

    update_burst(&update_ife->burst, recv_ts, h_local_ts, h_link_seq, pkt->data_size);

    //An ack is an empty packet meant only to update our interface's rx_time and packets_since_ack
    if((n_tun_hdr.type == TUNTYPE_ACK)) {
        free_packet(pkt);
        return SUCCESS;
    }
    //Process the ping even though we may not have an entry in our remote_nodes
    if((n_tun_hdr.type == TUNTYPE_PING)){
        handle_incoming_ping(from, pkt->created, ife, remote_ife, pkt->data, pkt->data_size);
        free_packet(pkt);
        return SUCCESS;
    }

    //Send an ack and return if the packet was only requesting an ack
    send_encap_packet_ife(TUNTYPE_ACK, "", 0, get_unique_id(), ife, remote_ife, &h_local_ts, 0);
    if((n_tun_hdr.type == TUNTYPE_ACKREQ)){
        free_packet(pkt);
        return SUCCESS;
    }

    if(packet_log_enabled && packet_log_file != NULL)
    {
        logPacket(&pkt->created, pkt->data_size, "INGRESS", ife, remote_ife);
    }

    return handle_ife_packet(pkt, ife, 1);
    
} // End function int handleInboundPacket()

int handle_nat_packet(struct packet * pkt, struct interface * ife)
{
    struct flow_tuple ft;
    fill_flow_tuple(pkt->data, &ft, 0);

    policy_entry pe;
    get_policy_by_tuple(&ft,  &pe, DIR_INGRESS);
    if(pe.action != POLICY_ACT_NAT) {
        free_packet(pkt);
        return SUCCESS;
    }
    struct iphdr * ip_hdr = (struct iphdr *)pkt->data;
    ip_hdr->daddr = tun->n_private_ip;
    compute_ip_checksum(ip_hdr);
    if(ip_hdr->protocol == 6) { 
        compute_tcp_checksum(&pkt->data[sizeof(struct iphdr)], pkt->data_size - sizeof(struct iphdr), ip_hdr->saddr, ip_hdr->daddr);
    }

    return handle_ife_packet(pkt, ife, 1);
}

int handle_ife_packet(struct packet *pkt, struct interface *ife, int allow_enqueue)
{
    struct flow_tuple ft;
    fill_flow_tuple(pkt->data, &ft, 1);

    struct flow_entry *fe = get_flow_entry(&ft);

    ife->rx_bytes += pkt->data_size;

    return handle_flow_packet(pkt, fe, 1);
}

int handle_flow_packet(struct packet * pkt, struct flow_entry * fe, int allow_enqueue) {
    //Packet queuing if a rate limit is violated
    if(fe->ingress.rate_control != NULL && !has_capacity(fe->ingress.rate_control)) {
        if(allow_enqueue)
            packet_queue_append(&fe->ingress.packet_queue_head, &fe->ingress.packet_queue_tail, pkt);
        return SEND_QUEUE;
    }

    if(pkt->data_size + TUNTAP_OFFSET > outbound_mtu) { 
        DEBUG_MSG("Tried to send packet larger than our send buffer %d", pkt->data_size);
        free_packet(pkt);
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

    struct iphdr *ip_hdr = (struct iphdr *)(pkt->data);
    unsigned short tun_info[2];
    tun_info[0] = 0; //flags
    tun_info[1] = ip_hdr->version == 6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);
    memcpy(send_buffer, tun_info, TUNTAP_OFFSET);


    memcpy( (char *)&send_buffer[TUNTAP_OFFSET], pkt->data, pkt->data_size);

    if( write(tun->tunnelfd, send_buffer, pkt->data_size + TUNTAP_OFFSET) < 0)
    {
        ERROR_MSG("write() failed");
        free_packet(pkt);
        return FAILURE;
    }

    // Update flow statistics
    update_flow_entry(fe);
    if(fe->ingress.rate_control != NULL) {
        update_tx_rate(fe->ingress.rate_control, pkt->data_size);
    }

    free_packet(pkt);
    return SUCCESS;
}

int handleOutboundPacket(struct tunnel * tun) 
{
    //Leave room for the TUNTAP header
    struct packet *pkt = alloc_packet(0, tunnel_mtu + TUNTAP_OFFSET);
    
    int read_size = read(tun->tunnelfd, pkt->data, pkt->tail_size);
    if (read_size >= 0) {
        packet_put(pkt, read_size);

        //Ignore the tuntap header
        packet_pull(pkt, TUNTAP_OFFSET);

        obtain_read_lock(&interface_list_lock);
        int output = send_packet(pkt, 1, 1);
        release_read_lock(&interface_list_lock);

        return output;
    } else {
        ERROR_MSG("read packet failed");
        free_packet(pkt);
    }

    return SUCCESS;
} // End function int handleOutboundPacket()

int send_packet(struct packet *pkt, int allow_ife_enqueue, int allow_flow_enqueue)
{
    struct flow_tuple ft;

    // Policy and Flow table
    fill_flow_tuple(pkt->data, &ft, 0);

    struct flow_entry *fe = get_flow_entry(&ft);
    if(fe == NULL) {
        fe = add_entry(&ft, 1);
    }

    update_flow_entry(fe);

    // Check for drop
    if((fe->egress.action & POLICY_ACT_MASK) == POLICY_ACT_DROP) {
        free_packet(pkt);
        return SUCCESS;
    }


    //Packet queuing if a flow rate limit is violated
    if(fe->egress.rate_control != NULL && !has_capacity(fe->egress.rate_control)) {
        if (allow_flow_enqueue)
            packet_queue_append(&fe->egress.packet_queue_head, &fe->egress.packet_queue_head, pkt);
        return SEND_QUEUE;
    }

    int node_id = get_unique_id();

    struct interface *dst_ife = select_dst_interface(fe);
    struct remote_node *remote_node = NULL;

    if(dst_ife == NULL)
        return FAILURE;
    if(fe->owner) {
        fe->egress.remote_link_id = dst_ife->index;
        fe->egress.remote_node_id = dst_ife->node_id;
    }
    remote_node = lookup_remote_node_by_id(dst_ife->node_id);

    if(remote_node == NULL) {
        DEBUG_MSG("Destination interface %s had bad remote_node id %d", dst_ife->name, dst_ife->node_id);
        return FAILURE;
    }


    // Send on all interfaces
    if((fe->egress.action & POLICY_OP_MASK) == POLICY_OP_DUPLICATE) {
        struct interface *local_ife = interface_list;
        struct interface *remote_ife;
        while(local_ife) {
            remote_ife = remote_node->head_interface;
            while(remote_ife) {
                send_encap_packet_ife(TUNTYPE_DATA, pkt->data, pkt->data_size, node_id, local_ife, remote_ife, NULL, remote_node->global_seq);
                remote_ife = remote_ife->next;
            }
            local_ife = local_ife->next;
        }
        remote_node->global_seq++;
        free_packet(pkt);
        return SUCCESS;
    }

    struct interface *src_ife = select_src_interface(fe);
    if(fe->owner && src_ife != NULL) {
        fe->egress.local_link_id = src_ife->index;
    }

    if (!src_ife) {
        if (allow_ife_enqueue)
            packet_queue_append(&tx_queue_head, &tx_queue_tail, pkt);
        return SEND_QUEUE;
    }

    int output = FAILURE;
    //Add a tunnel header to the packet
    if((fe->egress.action & POLICY_ACT_MASK) == POLICY_ACT_ENCAP) {
        output = send_encap_packet_ife(TUNTYPE_DATA, pkt->data, pkt->data_size, node_id, src_ife, dst_ife, NULL, remote_node->global_seq);
        remote_node->global_seq++;
    }
    else if((fe->egress.action & POLICY_ACT_MASK) == POLICY_ACT_NAT) {
        struct interface *src_ife = select_src_interface(fe);
        if(src_ife != NULL) {
            output = send_nat_packet(pkt->data, pkt->data_size, src_ife);
        }
    }
    //Update rate information for the flow entry
    if(output == SUCCESS && fe->egress.rate_control != NULL) {
        update_tx_rate(fe->egress.rate_control, pkt->data_size);
    }
    free_packet(pkt);
    return output;
}

int send_encap_packet_ife(uint8_t type, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife,
    uint32_t *remote_ts, uint32_t global_seq)
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

    return send_encap_packet_dst(type, packet, size, src_ife, &dst, update_ife, global_seq, remote_ts);
}

int send_encap_packet_dst_noinfo(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst)
{
    return send_encap_packet_dst(type, packet, size, src_ife, dst, NULL, 0, NULL);
}
int send_encap_packet_dst(uint8_t type, char *packet, int size, struct interface *src_ife,
    struct sockaddr_storage *dst, struct interface *update_ife, uint32_t global_seq, uint32_t *remote_ts)
{
    if(type == TUNTYPE_DATA) {
        struct flow_tuple ft;
        fill_flow_tuple(packet, &ft, 0);
        struct flow_entry *fe = get_flow_entry(&ft);

        if(fe != NULL && fe->owner && fe->requires_flow_info)
        {
            struct packet *info_pkt = alloc_packet(sizeof(struct flow_tuple) + sizeof(struct tunhdr_flow_info) * 2, 0);
            struct tunhdr_flow_info ingress_info;
            ingress_info.action = fe->ingress.action;
            ingress_info.local_link_id = fe->ingress.local_link_id;
            ingress_info.remote_link_id = fe->ingress.remote_link_id;
            ingress_info.rate_limit = 0;

            struct tunhdr_flow_info egress_info;
            egress_info.action = fe->egress.action;
            egress_info.local_link_id = fe->egress.local_link_id;
            egress_info.remote_link_id = fe->egress.remote_link_id;
            egress_info.rate_limit = 0;

            packet_push(info_pkt, sizeof(struct tunhdr_flow_info));
            *(struct tunhdr_flow_info *)info_pkt->data = ingress_info;

            packet_push(info_pkt, sizeof(struct tunhdr_flow_info));
            *(struct tunhdr_flow_info *)info_pkt->data = egress_info;
            packet_push(info_pkt, sizeof(struct flow_tuple));
            *(struct flow_tuple*)info_pkt->data = ft;
            send_encap_packet_dst(TUNTYPE_FLOW_INFO | TUNTYPE_DATA, info_pkt->data, info_pkt->data_size, src_ife, dst, NULL, 0, 0);
            free_packet(info_pkt);
            fe->requires_flow_info--;
        }
    }

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
        if(ife != NULL) {
            DEBUG_MSG("Tried to send packet over bad sockfd on interface %s", ife->name);
        }
        else {
            DEBUG_MSG("Tried to send packet over bad sockfd");
        }

        return FAILURE;
    }
    if((sendto(sockfd, packet, size, 0, (struct sockaddr *)dst, sizeof(struct sockaddr))) < 0)
    {
        if(ife != NULL) {
            ERROR_MSG("sendto failed fd %d (%s),  dst: %s, new_size: %d", sockfd, ife->name, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), size);
        }
        else {
            ERROR_MSG("sendto failed fd %d,  dst: %s, new_size: %d", sockfd, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), size);
        }

        return FAILURE;
    }
    if(ife != NULL) {
        ife->tx_bytes += size;
        update_tx_rate(&ife->rate_control, size);
    }
    return SUCCESS;
}


void service_tx_queue(struct packet ** head, struct timeval *now, int allow_ife_enqueue, int allow_flow_enqueue) {
    while (*head) {
        struct packet *pkt = *head;
        if(send_packet(pkt, allow_ife_enqueue, allow_flow_enqueue) == SEND_QUEUE) {
            /* If the packet has been queued for too long, give up on it.
             * Otherwise, leave it at the front of the queue and quit. */
            long age = timeval_diff(now, &pkt->created);
            if (age > MAX_TX_QUEUE_AGE) {
                free_packet(pkt);
            }
            else
                break;
        }
        packet_queue_dequeue(head);
    }
}

void service_flow_rx_queue(struct flow_entry * fe, struct timeval *now) {
    struct packet **head = &fe->ingress.packet_queue_head;
    while (*head) {
        struct packet *pkt = *head;
        if(handle_flow_packet(pkt, fe, 0) == SEND_QUEUE) {
            /* If the packet has been queued for too long, give up on it.
             * Otherwise, leave it at the front of the queue and quit. */
            long age = timeval_diff(now, &pkt->created);
            if (age > MAX_TX_QUEUE_AGE) {
                free_packet(pkt);
            }
            else
                break;
        }
        packet_queue_dequeue(head);
    }
}

int service_queues()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    struct flow_entry *flow_entry, *tmp;
    HASH_ITER(hh, get_flow_table(), flow_entry, tmp) {
        service_flow_rx_queue(flow_entry, &now);
        service_tx_queue(&flow_entry->egress.packet_queue_head, &now, 1, 0);
    }
    service_tx_queue(&tx_queue_head, &now, 0, 0);

    return 0;
}