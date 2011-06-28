#include <stdlib.h>
#include <libconfig.h>
#include <stropts.h>
#include <unistd.h>
#include <asm-generic/sockios.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sys/time.h>

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
#include "tunnel.h"

static int send_ping(struct interface* ife,
              const struct sockaddr* dest_addr, socklen_t dest_len);
static void* ping_thread_func(void* arg);
static int handle_incoming(int sockfd, int timeout);
static int send_second_response(const struct interface *ife, 
        const char *buffer, int len, const struct sockaddr *to, socklen_t to_len);
static void mark_inactive_interfaces();

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

    const unsigned short controller_port = 
            get_controller_base_port() + DATA_CHANNEL_OFFSET;

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
    get_controller_ip(controller_ip, sizeof(controller_ip));

    const unsigned short controller_port = 
            get_controller_base_port() + DATA_CHANNEL_OFFSET;

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

    sockfd = udp_bind_open(get_base_port(), ife->name);
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
    pkt->secret_word = get_secret_word();

    // Attempt to stuff GPS data into the packet
    if(fill_gps_payload(&pkt->gps) < 0) {
        pkt->type = PING_REQUEST;
        send_size = MIN_PING_PACKET_SIZE;
    } else {
        pkt->type = PING_REQUEST_WITH_GPS;
        send_size = PING_WITH_GPS_SIZE;
    }
   
    // Store a timestamp in the packet for calculating RTT.
    pkt->sender_ts = htonl(timeval_to_usec(0));
    pkt->receiver_ts = 0;

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
    int sockfd;

    sockfd = udp_bind_open(get_base_port(), 0);
    if(sockfd == FAILURE) {
        DEBUG_MSG("Ping thread cannot continue due to failure");
        return 0;
    }

    // We never want reads to hold up the thread.
    set_nonblock(sockfd, NONBLOCKING);

    ping_all_interfaces();
    time_t last_ping_time = time(0);

    unsigned int next_timeout = ping_interval;
    while(1) {
        struct timeval timeout;
        timeout.tv_sec = next_timeout;
        timeout.tv_usec = 0;

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        int result = select(sockfd+1, &read_set, 0, 0, &timeout);
        if(result > 0 && FD_ISSET(sockfd, &read_set)) {
            // Most likely we have an incoming ping response.
            handle_incoming(sockfd, ping_interval);
        } else if(result < 0) {
            ERROR_MSG("select failed for ping socket (%d)", sockfd);
        }

        int time_remaining = ping_interval - (time(0) - last_ping_time);
        if(time_remaining <= 0) {
            mark_inactive_interfaces();

            // It is time to send out another round of pings.
            ping_all_interfaces();
            last_ping_time = time(0);
        } else {
            next_timeout = time_remaining;
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

    unsigned link_id = ntohl(pkt->link_id);

    // TODO: interface_list is supposed to be locked, but I do not want to wait
    // for a lock before sending the response packet

    struct interface* ife = find_interface_by_index(interface_list, link_id);
    if(!ife) {
        DEBUG_MSG("Ping response for unknown interface %u", link_id);
        return 0;
    }

    // TODO: Verify identity of sender before sending the response.  This is
    // really important because a malicious host could trick us into sending
    // him our secret_word.
    
    if(send_second_response(ife, buffer, bytes, 
                (struct sockaddr *)&addr, addr_len) < 0) {
        ERROR_MSG("send_second_response failed");
    }

    int notif_needed = 0;

    uint32_t send_ts = ntohl(pkt->sender_ts);
    uint32_t recv_ts = timeval_to_usec(&recv_time);
    long diff = (long)recv_ts - (long)send_ts;

    // If the ping response is older than timeout seconds, we just ignore it.
    if((diff / USEC_PER_SEC) < timeout) {
        ife->avg_rtt = ema_update(ife->avg_rtt, (double)diff, 0.25);
        if(ife->state == INACTIVE) {
            change_interface_state(ife, ACTIVE);
            notif_needed = 1;
        }

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
    
    int sockfd = udp_bind_open(get_base_port(), ife->name);
    if(sockfd < 0) {
        return -1;
    }

    char response_buffer[MIN_PING_PACKET_SIZE];
    memcpy(response_buffer, buffer, MIN_PING_PACKET_SIZE);

    struct ping_packet *ping = (struct ping_packet *)
            (response_buffer + sizeof(struct tunhdr));

    ping->type = PING_SECOND_RESPONSE;
    ping->src_id = htons(get_unique_id());
    ping->secret_word = get_secret_word();
    ping->sender_ts = 0;

    int result = sendto(sockfd, response_buffer, 
            MIN_PING_PACKET_SIZE, 0, to, to_len);
    if(result < 0) {
        ERROR_MSG("sendto failed");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

static void mark_inactive_interfaces()
{
    int notif_needed = 0;

    obtain_read_lock(&interface_list_lock);

    struct interface* curr_ife = interface_list;
    while(curr_ife) {
        if(curr_ife->state == ACTIVE) {
            int32_t losses = (int32_t)curr_ife->next_ping_seq_no -
                (int32_t)curr_ife->last_ping_seq_no - 1;

            if(losses >= PING_LOSS_THRESHOLD) {
                DEBUG_MSG("Marking %s INACTIVE after %d ping losses",
                        curr_ife->name, losses);
                
                upgrade_read_lock(&interface_list_lock);
                change_interface_state(curr_ife, INACTIVE);
                downgrade_write_lock(&interface_list_lock);

                notif_needed = 1;
            }
        }

        assert(curr_ife != curr_ife->next);
        curr_ife = curr_ife->next;
    }

    release_read_lock(&interface_list_lock);

    if(notif_needed) {
        send_notification(1);
    }
}

