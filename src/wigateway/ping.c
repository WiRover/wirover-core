#include <stdlib.h>
#include <libconfig.h>
//#include <stropts.h>
#include <unistd.h>
#include <asm-generic/sockios.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "config.h"
#include "configuration.h"
#include "constants.h"
#include "contchan.h"
#include "datapath.h"
#include "debug.h"
#include "gps_handler.h"
#include "interface.h"
#include "icmp_ping.h"
#include "netlink.h"
#include "packet.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "state.h"
#include "timing.h"
#include "tunnel.h"

static void* ping_thread_func(void* arg);
static int send_second_response(struct interface *ife, 
                                const char *buffer, int len, struct interface *dst_ife);

static int          status_log_enabled = 0;
static int          running = 0;
static pthread_t    ping_thread;
static int          mtu = 1400;

int start_ping_thread()
{
    mtu = get_mtu();
    if(running) {
        DEBUG_MSG("Ping thread already running");
        return 0;
    }

    status_log_enabled = get_status_log_enabled();
    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result = pthread_create(&ping_thread, &attr, ping_thread_func, 0);
    if(result != 0) {
        ERROR_MSG("Creating thread failed");
        return FAILURE;
    }

    running = 1;

    pthread_attr_destroy(&attr);
    return 0;
}

/*
* SEND PING
*
* Locking: Assumes the calling thread has a read lock on the interface list.
*/
int send_ping(struct interface* ife)
{
    struct packet *pkt = alloc_packet(sizeof(struct tunhdr), MIN_PING_PACKET_SIZE + sizeof(struct gps_payload));

    packet_put(pkt, MIN_PING_PACKET_SIZE);

    struct ping_packet *ping_pkt = (struct ping_packet *)(pkt->data);
    ping_pkt->seq_no = htonl(ife->next_ping_seq_no++);
    ping_pkt->link_state = ife->state;
    ping_pkt->src_id = htons(get_unique_id());
    ping_pkt->link_id = htonl(ife->index);

    struct gps_payload *gps = (struct gps_payload *)
        ((char *)ping_pkt + sizeof(struct ping_packet));
    gps->next = PING_NO_PAYLOAD;

    // Attempt to stuff GPS data into the packet
    packet_put(pkt, sizeof(struct gps_payload));
    if(fill_gps_payload(gps) < 0) {
        ping_pkt->type = PING_REQUEST;
        packet_pull_tail(pkt, sizeof(struct gps_payload));
    } else {
        ping_pkt->type = PING_REQUEST | PING_GPS_PAYLOAD;
    }

    // Store a timestamp in the packet for calculating RTT.
    ping_pkt->sender_ts = htonl(timeval_to_usec(0));
    ping_pkt->receiver_ts = 0;
    fill_ping_digest(ping_pkt, pkt->data, pkt->data_size, private_key);

    if(send_encap_packet_ife(TUNTYPE_PING, pkt, ife, get_controller_ife(), NULL, 0)) {
        /* We get an error ENETUNREACH if we try pinging out an interface which
        * does not have an IP address.  That case is not interesting, so we
        * suppress the error message. */
        if(errno != ENETUNREACH)
            ERROR_MSG("sending ping packet on %s failed", ife->name);
        return -1;
    }

    get_monotonic_time(&ife->last_ping_time);

    return 0;
}

static int should_send_ping(struct interface *ife)
{
    if(!(state & GATEWAY_LEASE_OBTAINED) || ife->state == DEAD)
        return 0;
    int64_t elapsed_us = get_elapsed_us(&ife->last_ping_time);
    if(elapsed_us > ife->ping_interval * USECS_PER_SEC)
        return 1;

    return 0;
}

void* ping_thread_func(void* arg)
{   
    const unsigned int ping_interval = get_ping_interval();
    int stall_retry_interval = get_link_stall_retry_interval() * USECS_PER_MSEC;

    // Initialize this so that the first ping will be sent immediately.
    struct timeval last_ping_time;
    get_monotonic_time(&last_ping_time);

    int num_ifaces = 0;
    int curr_iface_pos = 0;

    unsigned ping_spacing = ping_interval * USECS_PER_SEC;

    struct timeval now;

    while(1) {

        get_monotonic_time(&now);

        obtain_read_lock(&interface_list_lock);

        num_ifaces = count_all_interfaces(interface_list);

        //Send retry packets over inactive interfaces
        struct interface *inactive_interface = interface_list;
        while(inactive_interface)
        {
            //TODO: This should instead send an ICMP ping to google's DNS or something
            if(!inactive_interface->connectivity)
            {
                send_icmp_ping(inactive_interface);
                inactive_interface->state = ACTIVE;
            }
            if(inactive_interface->state != ACTIVE && timeval_diff(&now, &inactive_interface->tx_time) >= stall_retry_interval){
                send_encap_packet_ife(TUNTYPE_ACKREQ, alloc_packet(sizeof(struct tunhdr),0), inactive_interface, get_controller_ife(), NULL, 0);
            }
            inactive_interface = inactive_interface->next;
        }

        release_read_lock(&interface_list_lock);

        if(curr_iface_pos >= num_ifaces) {
            curr_iface_pos = 0;
        }

        if(num_ifaces > 0)
            ping_spacing = ping_interval * USECS_PER_SEC / num_ifaces;
        else
            ping_spacing = ping_interval * USECS_PER_SEC;



        int64_t time_diff = timeval_diff(&now, &last_ping_time);
        if(time_diff >= ping_spacing) {
            obtain_read_lock(&interface_list_lock);
            struct interface *ife = find_interface_at_pos(
                interface_list, curr_iface_pos);
            if(ife && should_send_ping(ife)) {
                send_ping(ife);
            }
            release_read_lock(&interface_list_lock);

            memcpy(&last_ping_time, &now, sizeof(last_ping_time));

            curr_iface_pos++;
        }

        safe_usleep(stall_retry_interval);
    }

    running = 0;
    return 0;
}

/*
* HANDLE INCOMING
*
* Locking: Assumes the calling thread does not have a lock on the interface list.
*/
int handle_incoming_ping(struct sockaddr_storage *from_addr, struct timeval recv_time, struct interface *local_ife, struct interface *remote_ife, char *buffer, int size)
{
    if(size < MIN_PING_PACKET_SIZE) {
        DEBUG_MSG("Incoming packet was too small (%d bytes)", size);
    }

    struct ping_packet *pkt = (struct ping_packet *)(buffer);

    // TODO: interface_list is supposed to be locked, but I do not want to wait
    // for a lock before sending the response packet

    /* Under normal circumstances, we will send a ping response back to the
    * controller so that it can measure RTT.  The response will be suppressed
    * if there is an error condition or a secret_word mismatch. */
    int send_response = 1;

    /*
    * If the controller does not recognize our id (this can happen if the
    * controller is restarted), then it responds with the error bit set.  We
    * can re-establish state with the controller by sending a notification.
    */
    if(pkt->type == PING_RESPONSE_ERROR) {
        DEBUG_MSG("Controller responded with an error, will send a notification");
        send_response = 0;
    }

    if(iszero(pkt->digest, sizeof(pkt->digest))) {
        send_response = 0;
    } else if(verify_ping_sender(pkt, buffer, size, private_key) != 0) {
        DEBUG_MSG("SHA hash mismatch, ping packet discarded");
        return FAILURE;
    }

    unsigned link_id = ntohl(pkt->link_id);

    struct interface* ife = find_interface_by_index(interface_list, link_id);
    if(!ife) {
        DEBUG_MSG("Ping response for unknown interface %u", link_id);
        return SUCCESS;
    }

    if(send_response) {
        if(send_second_response(ife, buffer, size, get_controller_ife()) < 0) {
            ERROR_MSG("send_second_response failed");
        }
    }

    uint32_t send_ts = ntohl(pkt->sender_ts);
    uint32_t recv_ts = timeval_to_usec(&recv_time);
    uint32_t diff = (uint32_t)recv_ts - (uint32_t)send_ts;

    // If the ping response is older than the ping interval we ignore it.
    if(diff < (get_ping_interval() * USECS_PER_SEC)) {
        ife->est_uplink_bw = ewma_update(ife->est_uplink_bw, (double)int_to_bw(ntohl(pkt->est_bw)), BW_EWMA_WEIGHT);

        ife->last_ping_success = recv_time;
        ife->last_ping_seq_no = ntohl(pkt->seq_no);

        DEBUG_MSG("Ping on %s (%s) rtt %d avg_rtt %f bw %f",
            ife->name, ife->network, diff, ife->avg_rtt, ife->est_downlink_bw);
    }

    return 0;
}

/*
* Send a response back to the controller.  This allows the controller
* to measure RTT as well.
*
* Assumes the buffer is at least MIN_PING_PACKET_SIZE in length.
*/
static int send_second_response(struct interface *ife, 
                                const char *buffer, int len, struct interface *dst_ife)
{
    assert(len >= MIN_PING_PACKET_SIZE);

    int send_size = MIN_PING_PACKET_SIZE + sizeof(struct passive_payload);
    struct packet* pkt = alloc_packet(sizeof(struct tunhdr), send_size);
    if(!pkt) {
        DEBUG_MSG("out of memory");
        return -1;
    }
    packet_put(pkt, MIN_PING_PACKET_SIZE);
    memcpy(pkt->data, buffer, MIN_PING_PACKET_SIZE);

    struct ping_packet *ping = (struct ping_packet *)(pkt->data);

    ping->type = PING_SECOND_RESPONSE | PING_PASSIVE_PAYLOAD;
    ping->src_id = htons(get_unique_id());
    ping->sender_ts = 0;

    packet_put(pkt, sizeof(struct passive_payload));
    struct passive_payload *passive = (struct passive_payload *)
        ((char *)pkt->data + sizeof(struct ping_packet));

    if(fill_passive_payload(ife->name, passive) < 0) {
        packet_pull_tail(pkt, sizeof(struct ping_packet));
    }

    fill_ping_digest(ping, pkt->data, pkt->data_size, private_key);
    int result = send_encap_packet_ife(TUNTYPE_PING, pkt, ife, dst_ife, NULL, 0);
    //int result = sendto(sockfd, response, send_size, 0, to, to_len);

    if(result < 0) {
        ERROR_MSG("sendto failed");
        return -1;
    }
    return 0;
}
