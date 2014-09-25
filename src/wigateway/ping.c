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
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"

static void* ping_thread_func(void* arg);
static int send_second_response(struct interface *ife, 
                                const char *buffer, int len, struct interface *dst_ife);

static int          status_log_enabled = 0;
static int          running = 0;
static pthread_t    ping_thread;

int start_ping_thread()
{
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
* PING ALL INTERFACES
*
* Locking: Assumes the calling thread does not have a lock on the interface list.
*/
int ping_all_interfaces()
{
    int pings_sent = 0;

    struct sockaddr_storage dest_addr;
    unsigned dest_len;
    dest_len = build_data_sockaddr(get_controller_ife(), &dest_addr);
    if(dest_len < 0) {
        return FAILURE;
    }

    //We need a read lock on the interface list to prevent anyone from adding
    //or removing interfaces while we iterate over the list.
    obtain_read_lock(&interface_list_lock);

    struct interface* curr_ife = interface_list;
    while(curr_ife) {
        send_ping(curr_ife);

        assert(curr_ife != curr_ife->next);
        curr_ife = curr_ife->next;
    }

    release_read_lock(&interface_list_lock);
    return pings_sent;
}

/*
* SEND PING
*
* Locking: Assumes the calling thread has a read lock on the interface list.
*/
int send_ping(struct interface* ife)
{
    char *buffer = malloc(MAX_PING_PACKET_SIZE);
    if(!buffer) {
        DEBUG_MSG("out of memory");
        return FAILURE;
    }

    memset(buffer, 0, MAX_PING_PACKET_SIZE);
    unsigned send_size = MIN_PING_PACKET_SIZE;

    struct ping_packet *pkt = (struct ping_packet *)(buffer);
    pkt->seq_no = htonl(ife->next_ping_seq_no++);
    pkt->link_state = ife->state;
    pkt->src_id = htons(get_unique_id());
    pkt->link_id = htonl(ife->index);

    struct gps_payload *gps = (struct gps_payload *)
        ((char *)pkt + sizeof(struct ping_packet));
    gps->next = PING_NO_PAYLOAD;

    // Attempt to stuff GPS data into the packet
    if(fill_gps_payload(gps) < 0) {
        pkt->type = PING_REQUEST;
        send_size = MIN_PING_PACKET_SIZE;
    } else {
        pkt->type = PING_REQUEST | PING_GPS_PAYLOAD;
        send_size = MIN_PING_PACKET_SIZE + sizeof(struct gps_payload);
    }

    // Store a timestamp in the packet for calculating RTT.
    pkt->sender_ts = htonl(timeval_to_usec(0));
    pkt->receiver_ts = 0;
    fill_ping_digest(pkt, buffer, send_size, private_key);

    if(send_ife_packet(TUNTYPE_PING, buffer, send_size, get_unique_id(), ife, get_controller_ife())) {
        /* We get an error ENETUNREACH if we try pinging out an interface which
        * does not have an IP address.  That case is not interesting, so we
        * suppress the error message. */
        if(errno != ENETUNREACH)
            ERROR_MSG("sending ping packet on %s failed", ife->name);
        free(buffer);
        return -1;
    }
    pkt->type = PING_TAILGATE;
    send_size = MAX_PING_PACKET_SIZE;
    //Send a tailgate packet
    if(send_ife_packet(TUNTYPE_PING, buffer, send_size, get_unique_id(), ife, get_controller_ife())) {
        /* We get an error ENETUNREACH if we try pinging out an interface which
        * does not have an IP address.  That case is not interesting, so we
        * suppress the error message. */
        if(errno != ENETUNREACH)
            ERROR_MSG("sending ping packet on %s failed", ife->name);
        free(buffer);
        return -1;
    }

    // This last_ping_time timestamp will be compared to the timestamp in the ping
    // response packet to make sure the response is for the most recent
    // request.
    //ife->last_ping_time = now.tv_sec;

    gettimeofday(&ife->last_ping_time, NULL);

    free(buffer);
    return 0;
}

static int should_send_ping(const struct interface *ife)
{
    if(ife->state == DEAD)
        return 0;
    struct timeval now;
    gettimeofday(&now, NULL);
    if(now.tv_sec >= ife->last_ping_time.tv_sec + ife->ping_interval)
        return 1;

    return 0;
}

void* ping_thread_func(void* arg)
{   
    const unsigned int ping_interval = get_ping_interval();
    const unsigned int status_interval = 1;
    int stall_retry_interval = get_link_stall_retry_interval() * USECS_PER_MSEC;

    // Initialize this so that the first ping will be sent immediately.
    struct timeval last_ping_time = {
        .tv_sec = time(0) - ping_interval, .tv_usec = 0};
    struct timeval last_status_time = {
        .tv_sec = time(0) - status_interval, .tv_usec = 0};

    int num_ifaces = 0;
    int curr_iface_pos = 0;

    unsigned ping_spacing = ping_interval * USEC_PER_SEC;

    struct timeval now;

    while(1) {

        gettimeofday(&now, 0);

        obtain_read_lock(&interface_list_lock);

        num_ifaces = count_all_interfaces(interface_list);

        //Send retry packets over inactive interfaces
        struct interface *inactive_interface = interface_list;

        while(inactive_interface)
        {
            if(inactive_interface->state != ACTIVE && timeval_diff(&now, &inactive_interface->tx_time) >= stall_retry_interval){
                send_ife_packet(TUNTYPE_ACKREQ, "", 0, get_unique_id(), inactive_interface, get_controller_ife());
            }
            inactive_interface = inactive_interface->next;
        }

        release_read_lock(&interface_list_lock);

        if(curr_iface_pos >= num_ifaces) {
            curr_iface_pos = 0;
        }

        if(num_ifaces > 0)
            ping_spacing = ping_interval * USEC_PER_SEC / num_ifaces;
        else
            ping_spacing = ping_interval * USEC_PER_SEC;



        long time_diff = timeval_diff(&now, &last_ping_time);
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

        time_diff = timeval_diff(&now, &last_status_time);
        if(time_diff >= status_interval) {
            memcpy(&last_status_time, &now, sizeof(last_status_time));
            if(status_log_enabled)
            {
                obtain_read_lock(&interface_list_lock);
                dump_interfaces_to_file(interface_list, "/var/lib/wirover/ife_list");
                release_read_lock(&interface_list_lock);
            }
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
        return -1;
    }

    unsigned link_id = ntohl(pkt->link_id);

    struct interface* ife = find_interface_by_index(interface_list, link_id);
    if(!ife) {
        DEBUG_MSG("Ping response for unknown interface %u", link_id);
        return 0;
    }
    if(send_response) {
        if(send_second_response(ife, buffer, size, get_controller_ife()) < 0) {
            ERROR_MSG("send_second_response failed");
        }
    }

    uint32_t send_ts = ntohl(pkt->sender_ts);
    uint32_t recv_ts = timeval_to_usec(&recv_time);
    long diff = (long)recv_ts - (long)send_ts;

    // If the ping response is older than the ping interval we ignore it.
    if(diff < (get_ping_interval() * USEC_PER_SEC)) {
        ife->avg_rtt = ewma_update(ife->avg_rtt, (double)diff, RTT_EWMA_WEIGHT);

        gettimeofday(&ife->last_ping_success, NULL);
        ife->last_ping_seq_no = ntohl(pkt->seq_no);

        DEBUG_MSG("Ping on %s (%s) rtt %d avg_rtt %f", 
            ife->name, ife->network, diff, ife->avg_rtt);
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
    char *response = malloc(send_size);
    if(!response) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    memcpy(response, buffer, MIN_PING_PACKET_SIZE);

    struct ping_packet *ping = (struct ping_packet *)(response);

    ping->type = PING_SECOND_RESPONSE | PING_PASSIVE_PAYLOAD;
    ping->src_id = htons(get_unique_id());
    ping->sender_ts = 0;

    struct passive_payload *passive = (struct passive_payload *)
        ((char *)ping + sizeof(struct ping_packet));

    if(fill_passive_payload(ife->name, passive) < 0) {
        send_size = MIN_PING_PACKET_SIZE;
    }

    fill_ping_digest(ping, response, send_size, private_key);
    int result = send_ife_packet(TUNTYPE_PING, response, send_size, get_unique_id(), ife, dst_ife);
    //int result = sendto(sockfd, response, send_size, 0, to, to_len);

    free(response);

    if(result < 0) {
        ERROR_MSG("sendto failed");
        return -1;
    }
    return 0;
}
