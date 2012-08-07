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

#include "config.h"
#include "configuration.h"
#include "contchan.h"
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

static int send_ping(struct interface* ife,
              const struct sockaddr* dest_addr, socklen_t dest_len);
static void* ping_thread_func(void* arg);
static int handle_incoming(int sockfd, int timeout);
static int send_second_response(const struct interface *ife, 
        const char *buffer, int len, const struct sockaddr *to, socklen_t to_len);
static void mark_inactive_interfaces(int link_timeout);

static int          running;
static pthread_t    ping_thread;

int start_ping_thread()
{
    if(running) {
        DEBUG_MSG("Ping thread already running");
        return FAILURE;
    }

    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result;
    result = pthread_create(&ping_thread, &attr, ping_thread_func, 0);
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

    char controller_ip[INET6_ADDRSTRLEN];
    if(get_controller_ip(controller_ip, sizeof(controller_ip)) < 0)
        return FAILURE;

    const unsigned short controller_port = get_controller_data_port();

    struct sockaddr_storage dest_addr;
    unsigned dest_len;
    dest_len = build_sockaddr(controller_ip, controller_port, &dest_addr);
    if(dest_len < 0) {
        return FAILURE;
    }

    //We need a read lock on the interface list to prevent anyone from adding
    //or removing interfaces while we iterate over the list.
    obtain_read_lock(&interface_list_lock);

    struct interface* curr_ife = interface_list;
    while(curr_ife) {
        send_ping(curr_ife, (struct sockaddr*)&dest_addr, dest_len);

        assert(curr_ife != curr_ife->next);
        curr_ife = curr_ife->next;
    }

    release_read_lock(&interface_list_lock);
    return pings_sent;
}

/*
 * PING INTERFACE
 *
 * This is a more convenient method for initiating a connectivity test
 * from outside this module -- eg. to be used by the netlink module when
 * a link comes up.
 *
 * Locking: Assumes the calling thread has a read lock on the interface list.
 */
int ping_interface(struct interface* ife)
{
    char controller_ip[INET6_ADDRSTRLEN];
    if(get_controller_ip(controller_ip, sizeof(controller_ip)) < 0)
        return FAILURE;

    const unsigned short controller_port = get_controller_data_port();

    struct sockaddr_storage dest_addr;
    unsigned dest_len;
    dest_len = build_sockaddr(controller_ip, controller_port, &dest_addr);
    if(dest_len < 0) {
        return FAILURE;
    }

    if(send_ping(ife, (struct sockaddr*)&dest_addr, dest_len) == FAILURE) {
        return FAILURE;
    }

    return 0;
}   

/*
 * SEND PING
 *
 * Locking: Assumes the calling thread has a read lock on the interface list.
 */
static int send_ping(struct interface* ife, 
        const struct sockaddr* dest_addr, socklen_t dest_len)
{
    int sockfd;
    struct timeval now;
    int bytes;

    sockfd = udp_bind_open(get_data_port(), ife->name);
    if(sockfd == FAILURE) {
        return FAILURE;
    }

    char *buffer = malloc(MAX_PING_PACKET_SIZE);
    if(!buffer) {
        DEBUG_MSG("out of memory");
        return FAILURE;
    }

    memset(buffer, 0, MAX_PING_PACKET_SIZE);
    unsigned send_size = MIN_PING_PACKET_SIZE;

    struct tunhdr *tunhdr = (struct tunhdr *)buffer;
    tunhdr->flags = TUNFLAG_DONT_DECAP;

    struct ping_packet *pkt = (struct ping_packet *)
        (buffer + sizeof(struct tunhdr));
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

    fill_ping_digest(pkt, buffer + sizeof(struct tunhdr), 
            send_size - sizeof(struct tunhdr), private_key);

    bytes = sendto(sockfd, buffer, send_size, 0, dest_addr, dest_len);
    if(bytes < 0) {
        ERROR_MSG("sending ping packet on %s failed", ife->name);
        free(buffer);
        close(sockfd);
        return -1;
    }

    // This last_ping_time timestamp will be compared to the timestamp in the ping
    // response packet to make sure the response is for the most recent
    // request.
    upgrade_read_lock(&interface_list_lock);
    ife->last_ping_time = now.tv_sec;
    downgrade_write_lock(&interface_list_lock);

    free(buffer);
    close(sockfd);
    return 0;
}

void* ping_thread_func(void* arg)
{
    const unsigned int ping_interval = get_ping_interval();
    const unsigned int link_timeout = get_link_timeout();
    int sockfd;

    sockfd = udp_bind_open(get_data_port(), 0);
    if(sockfd == FAILURE) {
        DEBUG_MSG("Ping thread cannot continue due to failure");
        return 0;
    }

    // We never want reads to hold up the thread.
    set_nonblock(sockfd, NONBLOCKING);

    // Initialize this so that the first ping will be sent immediately.
    struct timeval last_ping_time = {
        .tv_sec = time(0) - ping_interval, .tv_usec = 0};

    int num_ifaces = 0;
    int curr_iface_pos = 0;

    unsigned ping_spacing = ping_interval * USEC_PER_SEC;
    unsigned next_timeout;

    while(1) {
        if(curr_iface_pos >= num_ifaces) {
            obtain_read_lock(&interface_list_lock);
            num_ifaces = count_all_interfaces(interface_list);
            release_read_lock(&interface_list_lock);
            
            curr_iface_pos = 0;

            if(num_ifaces > 0)
                ping_spacing = ping_interval * USEC_PER_SEC / num_ifaces;
            else
                ping_spacing = ping_interval * USEC_PER_SEC;
        }

        struct timeval now;
        gettimeofday(&now, 0);

        long time_diff = timeval_diff(&now, &last_ping_time);
        if(time_diff >= ping_spacing) {
            mark_inactive_interfaces(link_timeout);

            obtain_read_lock(&interface_list_lock);
            struct interface *ife = find_interface_at_pos(
                    interface_list, curr_iface_pos);
            if(ife) {
                ping_interface(ife);
            }
            release_read_lock(&interface_list_lock);

            memcpy(&last_ping_time, &now, sizeof(last_ping_time));
            next_timeout = ping_spacing;

            curr_iface_pos++;
        } else {
            // Set the timeout on select such that it will return in time for
            // the next ping.
            next_timeout = ping_spacing - time_diff;
        }

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        struct timeval timeout;
        set_timeval_usec(next_timeout, &timeout);

        int result = select(sockfd+1, &read_set, 0, 0, &timeout);
        if(result > 0 && FD_ISSET(sockfd, &read_set)) {
            handle_incoming(sockfd, ping_interval);
        } else if(result < 0) {
            ERROR_MSG("select failed for ping socket (%d)", sockfd);
        }
    }

    close(sockfd);
    running = 0;
    return 0;
}

/*
 * HANDLE INCOMING
 *
 * Locking: Assumes the calling thread does not have a lock on the interface list.
 */
static int handle_incoming(int sockfd, int timeout)
{
    int bytes;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[MAX_PING_PACKET_SIZE];

    bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0,
            (struct sockaddr*)&addr, &addr_len);
    if(bytes < 0) {
        ERROR_MSG("recvfrom failed");
        return -1;
    } else if(bytes < MIN_PING_PACKET_SIZE) {
        DEBUG_MSG("Incoming packet was too small (%d bytes)", bytes);
    }

    // The receive timestamp recorded by the kernel will be more accurate
    // than if we call gettimeofday() at this point.
    struct timeval recv_time;
    if(ioctl(sockfd, SIOCGSTAMP, &recv_time) == -1) {
        DEBUG_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&recv_time, 0);
    }

    struct ping_packet *pkt = (struct ping_packet *)
            (buffer + sizeof(struct tunhdr));

    int notif_needed = 0;

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
        notif_needed = 1;
    }

    if(iszero(pkt->digest, sizeof(pkt->digest))) {
        send_response = 0;
    } else if(verify_ping_sender(pkt, buffer + sizeof(struct tunhdr), 
                bytes - sizeof(struct tunhdr), private_key) != 0) {
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
        if(send_second_response(ife, buffer, bytes, 
                    (struct sockaddr *)&addr, addr_len) < 0) {
            ERROR_MSG("send_second_response failed");
        }
    }

    uint32_t send_ts = ntohl(pkt->sender_ts);
    uint32_t recv_ts = timeval_to_usec(&recv_time);
    long diff = (long)recv_ts - (long)send_ts;

    // If the ping response is older than timeout seconds, we just ignore it.
    if((diff / USEC_PER_SEC) < timeout) {
        ife->avg_rtt = ewma_update(ife->avg_rtt, (double)diff, RTT_EWMA_WEIGHT);
        if(ife->state == INIT_INACTIVE || ife->state == INACTIVE) {
            change_interface_state(ife, ACTIVE);
            notif_needed = 1;
        }

        char network[NETWORK_NAME_LENGTH];
        read_network_name(ife->name, network, sizeof(network));

        if(strncmp(network, ife->network, sizeof(network)) != 0) {
            // If we detect a different network name, send another notification.
            strncpy(ife->network, network, sizeof(ife->network));
            notif_needed = 1;
        }

        ife->last_ping_success = time(NULL);
        ife->last_ping_seq_no = ntohl(pkt->seq_no);

        DEBUG_MSG("Ping on %s (%s) rtt %d avg_rtt %f", 
                ife->name, ife->network, diff, ife->avg_rtt);
    }

    if(notif_needed) {
        send_notification(1);
    }

    return 0;
}

/*
 * Send a response back to the controller.  This allows the controller
 * to measure RTT as well.
 *
 * Assumes the buffer is at least MIN_PING_PACKET_SIZE in length.
 */
static int send_second_response(const struct interface *ife, 
        const char *buffer, int len, const struct sockaddr *to, socklen_t to_len)
{
    assert(len >= MIN_PING_PACKET_SIZE);
    
    int sockfd = udp_bind_open(get_data_port(), ife->name);
    if(sockfd < 0) {
        return -1;
    }

    int send_size = MIN_PING_PACKET_SIZE + sizeof(struct passive_payload);
    char *response = malloc(send_size);
    if(!response) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    memcpy(response, buffer, MIN_PING_PACKET_SIZE);

    struct ping_packet *ping = (struct ping_packet *)
            (response + sizeof(struct tunhdr));

    ping->type = PING_SECOND_RESPONSE | PING_PASSIVE_PAYLOAD;
    ping->src_id = htons(get_unique_id());
    ping->sender_ts = 0;

    struct passive_payload *passive = (struct passive_payload *)
        ((char *)ping + sizeof(struct ping_packet));

    if(fill_passive_payload(ife->name, passive) < 0) {
        send_size = MIN_PING_PACKET_SIZE;
    }
    
    fill_ping_digest(ping, response + sizeof(struct tunhdr), 
            send_size - sizeof(struct tunhdr), private_key);
    
    int result = sendto(sockfd, response, send_size, 0, to, to_len);

    free(response);

    if(result < 0) {
        ERROR_MSG("sendto failed");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

static void mark_inactive_interfaces(int link_timeout)
{
    int notif_needed = 0;
    time_t now = time(NULL);

    obtain_read_lock(&interface_list_lock);

    struct interface* curr_ife = interface_list;
    while(curr_ife) {
        if(curr_ife->state == ACTIVE && 
                (now - curr_ife->last_ping_success) >= link_timeout) {
            change_interface_state(curr_ife, INACTIVE);
            notif_needed = 1;
        }

        assert(curr_ife != curr_ife->next);
        curr_ife = curr_ife->next;
    }

    release_read_lock(&interface_list_lock);

    if(notif_needed) {
        send_notification(1);
    }
}


