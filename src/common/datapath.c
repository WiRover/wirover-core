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

int handle_packet(struct interface * ife, int sockfd);
int handle_ife_packet(struct packet *pkt, struct interface * ife, int is_nat);
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

uint32_t local_remap_address()
{
    return tun->n_private_ip | (~tun->n_netmask ^ 0x01000000);
}

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
                handle_packet(curr_ife, curr_ife->sockfd);
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

int handle_packet(struct interface * ife, int sockfd)
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
    get_recv_timestamp(sockfd, &arrival_time);
    pkt->created = arrival_time;

    ife->rx_time = arrival_time;
    ife->packets_since_ack = 0;
    change_interface_state(ife, ACTIVE);
    return handle_encap_packet(pkt, ife, &from);

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
    uint32_t h_global_seq = ntohl(n_tun_hdr.global_seq);
    uint32_t h_link_seq = ntohl(n_tun_hdr.link_seq);
    uint32_t h_path_ack = ntohl(n_tun_hdr.path_ack);
    uint32_t h_remote_ts = ntohl(n_tun_hdr.remote_ts);
    uint32_t h_local_ts = ntohl(n_tun_hdr.local_ts);

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
            print_flow_tuple(&ft);
            flow_tuple_invert(&ft);
            struct flow_entry *fe = get_flow_entry(&ft);
            if(fe == NULL) {
                DEBUG_MSG("Received flow error for unknown flow");
            }
            else {
                fe->requires_flow_info++;
                fe->owner = 1;
            }
        }
        free_packet(pkt);
        return SUCCESS;
    }

    struct interface *remote_ife = NULL;

    if(gw == NULL)
    {
        DEBUG_MSG("Sending error for bad node");
        free_packet(pkt);
        struct packet *error = alloc_packet(sizeof(struct tunhdr), 1);
        packet_put(error, 1);
        error->data[0]=  TUNERROR_BAD_NODE;
        int output = send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, ife, from);
        return output;
    }

    remote_ife = find_interface_by_index(gw->head_interface, link_id);
    if(remote_ife == NULL)
    {
        DEBUG_MSG("Sending error for bad link %d", link_id);
        free_packet(pkt);
        struct packet *error = alloc_packet(sizeof(struct tunhdr), 1);
        packet_put(error, 1);
        error->data[0]=  TUNERROR_BAD_LINK;
        int output = send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, ife, from);
        return output;
    }

    update_interface_public_address(remote_ife, (const struct sockaddr *)from, sizeof(struct sockaddr_storage));

    // If the flow is data, make sure we have an entry for it in our
    // flow table
    if(tun_type == TUNTYPE_DATA)
    {

        if(tun_ctl == TUNTYPE_FLOW_INFO)
        {
            add_entry_info(pkt, node_id);
            free_packet(pkt);
            return SUCCESS;
        }

        struct flow_tuple ft;
        fill_flow_tuple(pkt->data, &ft, 1);

        struct flow_entry *fe = get_flow_entry(&ft);
        if(fe == NULL) {
            DEBUG_MSG("Bad flow");
            print_flow_tuple(&ft);
            free_packet(pkt);
            struct packet *error = alloc_packet(sizeof(struct tunhdr), sizeof(struct flow_tuple) + 1);
            packet_put(error, sizeof(struct flow_tuple) + 1);
            error->data[0] = TUNERROR_BAD_FLOW;
            *(struct flow_tuple *)&error->data[1] = ft;
            int output = send_encap_packet_dst_noinfo(TUNTYPE_ERROR, error, ife, from);
            return output;
        }
        if(!fe->owner) {
            fe->ingress.remote_link_id = link_id;
            fe->ingress.remote_node_id = node_id;
            fe->ingress.local_link_id = ife->index;
        }
        fe->ingress.count++;
        fe->requires_flow_info = 0;
    }

    //Remote_ts is the remote send time in our local clock domain
    uint32_t recv_ts = timeval_to_usec(&pkt->created);
    if(h_remote_ts != 0) {
        uint32_t diff = (uint32_t)recv_ts - (uint32_t)h_remote_ts;

        ife->avg_rtt = ewma_update(ife->avg_rtt, (double)diff, RTT_EWMA_WEIGHT);
    }

    // Estimate packet size / queueing delay
    if(pkt->data_size > 800 && h_local_ts != 0) {
        uint32_t *current = cbuffer_current(&ife->rtt_buffer);
        uint32_t diff = (uint32_t)((uint32_t)h_local_ts - (uint32_t)recv_ts);
        if(*current == 0 || diff < (uint32_t)*current)
        {
            *current = diff;
        }
        uint32_t queing_delay = diff - cbuffer_min(&ife->rtt_buffer);
        if(queing_delay != 0) {
            ife->base_rtt_diff = ewma_update(ife->base_rtt_diff, (double)queing_delay, RTT_EWMA_WEIGHT);
        }
        if(ife->base_rtt_diff != 0) {
            ife->est_downlink_bw = ewma_update(ife->est_downlink_bw, (double)pkt->data_size / (ife->base_rtt_diff) * 8.0, BW_EWMA_WEIGHT);
        }
    }

    // Verify the packet isn't a duplicate. Even if it is, send an ack
    // so that the remote link won't stall
    if(pb_add_seq_num(gw->rec_seq_buffer, h_global_seq) == DUPLICATE) {
        struct packet * ack = alloc_packet(sizeof(struct tunhdr), 0);
        send_encap_packet_ife(TUNTYPE_ACK | TUNTYPE_DUPLICATE, ack, ife, remote_ife, &h_local_ts, 0);
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
    if((tun_type == TUNTYPE_ACK)) {
        free_packet(pkt);
        return SUCCESS;
    }
    //Process the ping even though we may not have an entry in our remote_nodes
    if((tun_type == TUNTYPE_PING)){
        handle_incoming_ping(from, pkt->created, ife, remote_ife, pkt->data, pkt->data_size);
        free_packet(pkt);
        return SUCCESS;
    }

    //Send an ack and return if the packet was only requesting an ack
    struct packet *ack = alloc_packet(sizeof(struct tunhdr), 0);
    send_encap_packet_ife(TUNTYPE_ACK, ack, ife, remote_ife, &h_local_ts, 0);
    if((tun_type == TUNTYPE_ACKREQ)){
        free_packet(pkt);
        return SUCCESS;
    }

    if(packet_log_enabled && packet_log_file != NULL)
    {
        logPacket(&pkt->created, pkt->data_size, "INGRESS", ife, remote_ife);
    }

    return handle_ife_packet(pkt, ife, 1);
    
} // End function int handleInboundPacket()

int handle_ife_packet(struct packet *pkt, struct interface *ife, int allow_enqueue)
{
    struct flow_tuple ft;
    fill_flow_tuple(pkt->data, &ft, 1);

    struct flow_entry *fe = get_flow_entry(&ft);

    ife->rx_bytes += pkt->data_size;

    return handle_flow_packet(pkt, fe, 1);
}

int handle_flow_packet(struct packet * pkt, struct flow_entry * fe, int allow_enqueue) {
    if(fe == NULL) {
        DEBUG_MSG("Handle packet called with null flow entry");
        free_packet(pkt);
        return FAILURE;
    }
    //Packet queuing if a rate limit is violated
    struct rate_control *rate_control = fe->ingress.rate_control;
    if(rate_control != NULL && !has_capacity(rate_control)) {
        if(allow_enqueue)
            packet_queue_append(&rate_control->packet_queue_head, &rate_control->packet_queue_tail, pkt);
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
#ifdef GATEWAY
    struct iphdr *ip_hdr = (struct iphdr *)(pkt->data);
    if(fe->remap_address != 0)
    {
        ip_hdr->daddr = fe->remap_address;
        compute_ip_checksum(ip_hdr);
        compute_transport_checksum(pkt);
    }
#endif
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
    if(fe->ingress.rate_control != NULL) {
        update_tx_rate(fe->ingress.rate_control, pkt->data_size);
    }
    update_flow_entry(fe);

    free_packet(pkt);
    return SUCCESS;
}

int handleOutboundPacket(struct tunnel * tun) 
{
    //Leave room for the TUNTAP header and a possible tunnel header for later
    struct packet *pkt = alloc_packet(sizeof(struct tunhdr) - TUNTAP_OFFSET, tunnel_mtu + TUNTAP_OFFSET);
    
    int read_size = read(tun->tunnelfd, pkt->data, pkt->tail_size);
    if (read_size >= 0) {
        packet_put(pkt, read_size);

        //Ignore the tuntap header
        packet_pull(pkt, TUNTAP_OFFSET);

#ifdef GATEWAY
        uint32_t dst = ((struct iphdr*)pkt->data)->daddr;
        if((dst & tun->n_netmask) == (tun->n_private_ip & tun->n_netmask))
        {
            if(dst == local_remap_address())
                ((struct iphdr*)pkt->data)->daddr = tun->n_private_ip;
            struct flow_tuple ft;
            fill_flow_tuple(pkt->data, &ft, 1);
            struct flow_entry *fe = get_flow_entry(&ft);
            if(fe != NULL)
                return handle_flow_packet(pkt, fe, 1);
            else
            {
                free_packet(pkt);
                return SUCCESS;
            }
        }
#endif

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
    int remap_address = 0;
#ifdef GATEWAY
    struct iphdr * ip_hdr = (struct iphdr*)pkt->data;
    remap_address = ip_hdr->saddr;
    ip_hdr->saddr &= ~tun->n_netmask;
    ip_hdr->saddr |= (tun->n_netmask & tun->n_private_ip);
    compute_ip_checksum(ip_hdr);
    compute_transport_checksum(pkt);
#endif
    struct flow_tuple ft;

    // Policy and Flow table
    fill_flow_tuple(pkt->data, &ft, 0);

    struct flow_entry *fe = get_flow_entry(&ft);
    if(fe == NULL) {
        fe = add_entry(&ft, 1, remap_address);
    }

    update_flow_entry(fe);

    // Check for drop
    if(fe->egress.action == POLICY_ACT_DROP) {
        free_packet(pkt);
        return SUCCESS;
    }

    //Packet queuing if a flow rate limit is violated
    struct rate_control *rate_control = fe->egress.rate_control;
    if(rate_control != NULL && !has_capacity(rate_control)) {
        if(allow_flow_enqueue)
            packet_queue_append(&rate_control->packet_queue_head, &rate_control->packet_queue_tail, pkt);
        return SEND_QUEUE;
    }

    struct interface *dst_ife[8];
    int dst_ife_count = select_dst_interface(fe, dst_ife, sizeof(dst_ife));

    //TODO: Check the interface rate limit and queue if needed
    //if (!src_ife) {
    //    if (allow_ife_enqueue)
    //        packet_queue_append(&tx_queue_head, &tx_queue_tail, pkt);
    //    return SEND_QUEUE;
    //}

    struct interface *src_ife[8];
    int src_ife_count = select_src_interface(fe, src_ife, sizeof(src_ife));

    int output = FAILURE;
    if(src_ife_count > 0) {
        //Add a tunnel header to the packet
        if(fe->egress.action == POLICY_ACT_ENCAP) {
            if(dst_ife_count > 0) {
                //TODO: This only works where the dst_ifes are all from the same remote_node
                //perhaps change this functionality
                struct remote_node *remote_node = lookup_remote_node_by_id(dst_ife[0]->node_id);
                if(remote_node == NULL) {
                    DEBUG_MSG("Destination interface %s had bad remote_node id %d", dst_ife[0]->name, dst_ife[0]->node_id);
                    free_packet(pkt);
                    return FAILURE;
                }
                for(int i = 0; i < src_ife_count; i++)
                {
                    for(int j = 0; j < dst_ife_count; j++)
                    {
                        send_encap_packet_ife(TUNTYPE_DATA, clone_packet(pkt), src_ife[i], dst_ife[j], NULL, remote_node->global_seq);
                    }
                }
                remote_node->global_seq++;
                output = SUCCESS;
            }
        }
        else if(fe->egress.action == POLICY_ACT_NAT) {
            output = send_nat_packet(clone_packet(pkt), src_ife[0]);
        }
        //Update rate information for the flow entry
        if(output == SUCCESS && fe->egress.rate_control != NULL) {
            update_tx_rate(fe->egress.rate_control, pkt->data_size);
        }
    }
    free_packet(pkt);
    return output;
}

int send_encap_packet_ife(uint8_t type, struct packet *pkt, struct interface *src_ife, struct interface *dst_ife,
    uint32_t *remote_ts, uint32_t global_seq)
{
    if(dst_ife == NULL || src_ife == NULL)
    {
        free_packet(pkt);
        return FAILURE;
    }
    
    if(type == TUNTYPE_DATA && packet_log_enabled && packet_log_file != NULL){
        struct timeval tv;
        get_monotonic_time(&tv);
        logPacket(&tv, pkt->data_size, "EGRESS", src_ife, dst_ife);
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
    if(type == TUNTYPE_DATA && update_ife->state == ACTIVE) {
        obtain_write_lock(&update_ife->rt_buffer.rwlock);
        pb_add_packet(&update_ife->rt_buffer, update_ife->local_seq, clone_packet(pkt));
        release_write_lock(&update_ife->rt_buffer.rwlock);
    }

    return send_encap_packet_dst(type, pkt, src_ife, &dst, update_ife, global_seq, remote_ts);
}

int send_encap_packet_dst_noinfo(uint8_t type, struct packet *pkt, struct interface *src_ife,
    struct sockaddr_storage *dst)
{
    return send_encap_packet_dst(type, pkt, src_ife, dst, NULL, 0, NULL);
}
int send_encap_packet_dst(uint8_t type, struct packet *pkt, struct interface *src_ife,
    struct sockaddr_storage *dst, struct interface *update_ife, uint32_t global_seq, uint32_t *remote_ts)
{
    if(type == TUNTYPE_DATA) {
        struct flow_tuple ft;
        fill_flow_tuple(pkt->data, &ft, 0);
        struct flow_entry *fe = get_flow_entry(&ft);

        if(fe != NULL && fe->owner && fe->requires_flow_info > 0)
        {
            struct packet *info_pkt = alloc_packet(sizeof(struct tunhdr) + sizeof(struct flow_tuple) + sizeof(struct tunhdr_flow_info) * 2, 0);
            fill_flow_info(fe, info_pkt);
            send_encap_packet_dst(TUNTYPE_FLOW_INFO | TUNTYPE_DATA, info_pkt, src_ife, dst, NULL, 0, 0);
            fe->requires_flow_info--;
        }

        fe->egress.count++;
    }

    int output = FAILURE;
    char new_packet[pkt->data_size + sizeof(struct tunhdr)];
    memset(new_packet, 0, sizeof(new_packet));
    add_tunnel_header(type, pkt, src_ife, update_ife, global_seq, remote_ts);
    output = send_ife_packet(pkt, update_ife, src_ife->sockfd, (struct sockaddr *)dst);
    if(output == FAILURE) { return FAILURE; }
    src_ife->packets_since_ack++;
#ifdef GATEWAY
    struct timeval tv;
    get_monotonic_time(&tv);
    if(src_ife->packets_since_ack == 3)
    {
        src_ife->st_time = tv;
    }
    if(src_ife->packets_since_ack >= 3 && timeval_diff(&tv, &src_ife->st_time) > (src_ife->avg_rtt + 100 * USECS_PER_MSEC) * 2){
        change_interface_state(src_ife, INACTIVE);
    }
#endif
    get_monotonic_time(&src_ife->tx_time);
    return SUCCESS;
}

int send_nat_packet(struct packet *pkt, struct interface *src_ife) {
    int sockfd = src_ife->raw_sockfd;
    struct iphdr * ip_hdr = ((struct iphdr*)pkt->data);
    uint32_t dst_ip = ip_hdr->daddr;
    uint32_t *src_ip = &ip_hdr->saddr;
    if(*src_ip == tun->n_private_ip)
    {
        *src_ip = local_remap_address();
        compute_ip_checksum(ip_hdr);
    }
    compute_transport_checksum(pkt);

    //Determine the destination
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(struct sockaddr_in));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip;

    return send_ife_packet(pkt, src_ife, sockfd, (struct sockaddr *)&dst);
}

int send_ife_packet(struct packet *pkt, struct interface *ife, int sockfd, struct sockaddr * dst)
{
    int output = FAILURE;
    if(sockfd == 0) {
        if(ife != NULL) {
            DEBUG_MSG("Tried to send packet over bad sockfd on interface %s", ife->name);
        }
        else {
            DEBUG_MSG("Tried to send packet over bad sockfd");
        }
        goto free_return;
    }
    if((sendto(sockfd, pkt->data, pkt->data_size, 0, (struct sockaddr *)dst, sizeof(struct sockaddr))) < 0)
    {
        if(ife != NULL) {
            ERROR_MSG("sendto failed fd %d (%s),  dst: %s, new_size: %d", sockfd, ife->name, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), pkt->data_size);
        }
        else {
            ERROR_MSG("sendto failed fd %d,  dst: %s, new_size: %d", sockfd, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), pkt->data_size);
        }
        goto free_return;
    }
    output = SUCCESS;
    if(ife != NULL) {
        ife->tx_bytes += pkt->data_size;
        update_tx_rate(&ife->egress_rate_control, pkt->data_size);
    }

free_return:
    free_packet(pkt);
    return output;
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

void service_flow_rx_queue(struct flow_entry *fe, struct timeval *now) {
    if(fe->ingress.rate_control == NULL)
        return;
    struct packet **head = &fe->ingress.rate_control->packet_queue_head;
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
    get_monotonic_time(&now);
    struct flow_entry *flow_entry, *tmp;
    HASH_ITER(hh, get_flow_table(), flow_entry, tmp) {
        if(flow_entry->ingress.rate_control != NULL)
            service_flow_rx_queue(flow_entry, &now);
        if(flow_entry->egress.rate_control != NULL)
            service_tx_queue(&flow_entry->egress.rate_control->packet_queue_head, &now, 1, 0);
    }
    //TODO: Handle the queues on each interface

    return 0;
}
