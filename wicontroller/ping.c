#include <libconfig.h>
#include <stropts.h>
#include <unistd.h>
#include <asm-generic/sockios.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netdb.h>

#include "config.h"
#include "configuration.h"
#include "database.h"
#include "debug.h"
#include "gateway.h"
#include "interface.h"
#include "kernel.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "tunnel.h"
#include "uthash.h"
#include "utlist.h"

static void* ping_thread_func(void* arg);
static int handle_incoming(int sockfd);
static unsigned char ping_request_type(const char *buffer, int len);
static int send_response(int sockfd, const struct gateway *gw,
        unsigned char type, const char *buffer, 
        int len, const struct sockaddr *to, socklen_t to_len);
static void process_ping_request(char *buffer, int len, 
        const struct sockaddr *from, socklen_t from_len);
static void process_ping_response(char *buffer, int len, 
        const struct sockaddr *from, socklen_t from_len,
        const struct timeval *recv_time);
static void remove_stale_links(int link_timeout, int node_timeout);

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

void* ping_thread_func(void* arg)
{
    const unsigned short base_port = get_base_port();
    int sockfd;

    int link_timeout = DEFAULT_LINK_TIMEOUT;
    int node_timeout = DEFAULT_NODE_TIMEOUT;

    const config_t *config = get_config();
    if(config) {
        config_lookup_int(config, "link-timeout", &link_timeout);
        if(link_timeout <= 0) {
            DEBUG_MSG("Invalid value for link-timeout (%d)", link_timeout);
            link_timeout = DEFAULT_LINK_TIMEOUT;
        }

        config_lookup_int(config, "node-timeout", &node_timeout);
        if(node_timeout <= 0) {
            DEBUG_MSG("Invalid value for node-timeout (%d)", node_timeout);
            node_timeout = DEFAULT_NODE_TIMEOUT;
        }
    }

    sockfd = udp_bind_open(base_port, 0);
    if(sockfd == FAILURE) {
        DEBUG_MSG("Ping thread cannot continue due to failure");
        return 0;
    }

    // We never want reads to hold up the thread.
    set_nonblock(sockfd, NONBLOCKING);

    int timeout_sec = (link_timeout < node_timeout) ? 
        link_timeout : node_timeout;

    while(1) {
        struct timeval timeout;
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        int result = select(sockfd+1, &read_set, 0, 0, &timeout);
        if(result > 0 && FD_ISSET(sockfd, &read_set)) {
            // Most likely we have an incoming ping request.
            handle_incoming(sockfd);
        } else if(result < 0) {
            ERROR_MSG("select failed for ping socket (%d)", sockfd);
        }

        remove_stale_links(link_timeout, node_timeout);
    }

    close(sockfd);
    running = 0;
    return 0;
}

static int handle_incoming(int sockfd)
{
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    char buffer[MAX_PING_PACKET_SIZE];
    struct timeval recv_time;

    int bytes_recvd = recvfrom(sockfd, buffer, sizeof(buffer), 0,
            (struct sockaddr*)&from, &from_len);
    if(bytes_recvd < 0) {
        ERROR_MSG("recvfrom failed (socket %d)", sockfd);
        return -1;
    }

    unsigned char type = ping_request_type(buffer, bytes_recvd);
    
    const struct ping_packet *ping = (struct ping_packet *)
        (buffer + sizeof(struct tunhdr));
    unsigned short node_id = ntohs(ping->src_id);
    struct gateway *gw = 0;
    if(node_id != 0)
        gw = lookup_gateway_by_id(node_id);

    switch(type) {
        case PING_REQUEST:
        case PING_REQUEST_WITH_GPS:
            if(send_response(sockfd, gw, PING_RESPONSE, buffer, bytes_recvd, 
                        (struct sockaddr *)&from, from_len) < 0) {
                ERROR_MSG("Failed to send ping response");
                return 0;
            }

            process_ping_request(buffer, bytes_recvd, 
                    (struct sockaddr *)&from, from_len);
            break;
        case PING_REQUEST_WITH_ERROR:
            if(send_response(sockfd, 0, PING_RESPONSE_WITH_ERROR, buffer, 
                        bytes_recvd, (struct sockaddr *)&from, from_len) < 0) {
                ERROR_MSG("Failed to send ping response");
                return 0;
            }

            break;
        case PING_SECOND_RESPONSE:
            // The receive timestamp recorded by the kernel will be more accurate
            // than if we call gettimeofday() at this point.
            if(ioctl(sockfd, SIOCGSTAMP, &recv_time) == -1) {
                DEBUG_MSG("ioctl SIOCGSTAMP failed");
                gettimeofday(&recv_time, 0);
            }
                    
            process_ping_response(buffer, bytes_recvd,
                    (struct sockaddr *)&from, from_len, &recv_time);
            break;
        default:
            break;
    }

    return 0;
}

/*
 * Do minimal preprocessing to determing the type of ping packet
 * and whether it is valid or not.
 *
 * Returns PING_INVALID if the ping packet is invalid, otherwise returns
 * one of the following:
 *
 * PING_REQUEST
 * PING_REQUEST_WITH_GPS
 * PING_REQUEST_WITH_ERROR
 * PING_RESPONSE
 * PING_SECOND_RESPONSE
 */
static unsigned char ping_request_type(const char *buffer, int len)
{
    if(len < MIN_PING_PACKET_SIZE)
        return PING_INVALID;
    
    const struct ping_packet *ping = (struct ping_packet *)
        (buffer + sizeof(struct tunhdr));

    /* node_id == 0 is invalid, gateway should have received a non-zero id from
     * the root server. */
    unsigned short node_id = ntohs(ping->src_id);
    if(node_id == 0)
        return PING_INVALID;

    struct gateway *gw = lookup_gateway_by_id(node_id);

    /* This verifies the identity of the ping sender.  A secret_word of zero is
     * acceptable, but the sender will not be trusted in that case.  Zero is
     * used during the startup procedure before the control channel has been
     * established.  A non-zero secret word must match or the ping packet is
     * dropped. */
    if(ping->secret_word && gw && ping->secret_word != gw->secret_word) {
        DEBUG_MSG("Secret word mismatch for node %hu", node_id);
        return PING_INVALID;
    } else if(ping->secret_word && !gw) {
        // This can happen if the controller was restarted.  We will send a
        // response with the error bit set so that the gateway will know to
        // send a new notification.
        DEBUG_MSG("Unrecognized gateway (%hu)", node_id);
        return PING_REQUEST_WITH_ERROR;
    }

    return ping->type;
}

/*
 * Send a ping response.
 *
 * Assumes the buffer is at least MIN_PING_PACKET_SIZE in length.
 */
static int send_response(int sockfd, const struct gateway *gw,
        unsigned char type, const char *buffer, 
        int len, const struct sockaddr *to, socklen_t to_len)
{
    assert(len >= MIN_PING_PACKET_SIZE);

    char response_buffer[MIN_PING_PACKET_SIZE];
    memcpy(response_buffer, buffer, MIN_PING_PACKET_SIZE);

    struct ping_packet *ping = (struct ping_packet *)
        (response_buffer + sizeof(struct tunhdr));

    ping->type = type;
    ping->src_id = htons(get_unique_id());
    ping->secret_word = (gw ? gw->my_secret_word : 0);
    ping->receiver_ts = htonl(timeval_to_usec(0));

    return sendto(sockfd, response_buffer, MIN_PING_PACKET_SIZE, 0, to, to_len);
}

/*
 * Use the ping packet to update the list of links for a gateway.  If the link
 * is absent in our list, we can add it as an active interface, or if the link
 * was present but with a different IP address, we can update it.  The latter
 * case is especially relevent when the gateway is behind a NAT.
 */
static void process_ping_request(char *buffer, int len, 
        const struct sockaddr *from, socklen_t from_len)
{
    struct ping_packet *ping = (struct ping_packet *)
        (buffer + sizeof(struct tunhdr));

    unsigned short node_id = ntohs(ping->src_id);

    struct gateway *gw = lookup_gateway_by_id(node_id);
    if(!gw)
        return;

    if(ping->secret_word == 0 || ping->secret_word != gw->secret_word)
        return;

    gw->last_ping_time = time(0);

    unsigned link_id = ntohl(ping->link_id);
    struct interface *ife = 
        find_interface_by_index(gw->head_interface, link_id);

    // TODO: Add IPv6 support
    struct sockaddr_in from_in;
    if(sockaddr_to_sockaddr_in(from, from_len, &from_in) < 0) {
        char p_ip[INET6_ADDRSTRLEN];
        getnameinfo(from, from_len, p_ip, sizeof(p_ip), 0, 0, NI_NUMERICHOST);

        DEBUG_MSG("Unable to add interface with address %s (IPv6?)", p_ip);
        return;
    }
        
    if(ife) {
        /* The main reason for this check is if the gateway is behind a NAT,
         * then the IP address and port that it sends in its notification are
         * not the same as its public IP address and port. */
        if(memcmp(&ife->public_ip, &from_in.sin_addr, sizeof(struct in_addr)) ||
                ife->data_port != from_in.sin_port) {
            struct in_addr private_ip;
            ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&private_ip.s_addr);
            
            DEBUG_MSG("Changing node %hu link %hu from %x:%hu to %x:%hu",
                    gw->unique_id, ife->index,
                    ntohl(ife->public_ip.s_addr), ntohs(ife->data_port),
                    ntohl(from_in.sin_addr.s_addr), ntohs(from_in.sin_port));

            if(ife->state == ACTIVE)
                gw->active_interfaces--;
            virt_remove_remote_link(&private_ip, &ife->public_ip);

            memcpy(&ife->public_ip, &from_in.sin_addr, sizeof(struct in_addr));
            ife->data_port  = from_in.sin_port;
            ife->state      = ping->link_state;

            if(ife->state == ACTIVE) {
                gw->active_interfaces++;
                virt_add_remote_link(&private_ip, &from_in.sin_addr,
                    from_in.sin_port);
            }

            db_update_link(gw, ife);
        }
    } else {
        /* The main reason for adding missing links on ping packets is if
         * the controller is restarted (the list of links is cleared).
         * 
         * TODO: Instead, write state to a file on exit and read the file
         * on start up. */
        ife = alloc_interface();
        if(!ife) {
            DEBUG_MSG("out of memory");
            return;
        }

        ife->index = ntohl(ping->link_id);
        strncpy(ife->name, "unknown", sizeof(ife->name));
        strncpy(ife->network, "unknown", sizeof(ife->network));
        memcpy(&ife->public_ip, &from_in.sin_addr, sizeof(struct in_addr));
        ife->data_port = from_in.sin_port;
        ife->state = ping->link_state;

        DL_APPEND(gw->head_interface, ife);

        if(ife->state == ACTIVE) {
            struct in_addr private_ip;
            ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&private_ip.s_addr);

            gw->active_interfaces++;
            virt_add_remote_link(&private_ip, &from_in.sin_addr, 
                    from_in.sin_port);
        }

        db_update_link(gw, ife);
    }

    ife->last_ping_time = time(0);

    if(ping->type == PING_REQUEST_WITH_GPS && len >= PING_WITH_GPS_SIZE) {
        DEBUG_MSG("Node %hu gps %f, %f", node_id,
                ping->gps.latitude, ping->gps.longitude);
        db_update_gps(gw, &ping->gps);
    }
}

/*
 * Use the ping response do determine link RTT.
 */
static void process_ping_response(char *buffer, int len, 
        const struct sockaddr *from, socklen_t from_len,
        const struct timeval *recv_time)
{
    struct ping_packet *ping = (struct ping_packet *)
        (buffer + sizeof(struct tunhdr));

    unsigned short node_id = ntohs(ping->src_id);

    struct gateway *gw = lookup_gateway_by_id(node_id);
    if(!gw)
        return;

    if(ping->secret_word == 0 || ping->secret_word != gw->secret_word)
        return;

    gw->last_ping_time = time(0);

    unsigned link_id = ntohl(ping->link_id);
    struct interface *ife = 
        find_interface_by_index(gw->head_interface, link_id);
    if(!ife) {
        DEBUG_MSG("Ping response from missing interface on node %hu", node_id);
        return;
    }

    uint32_t send_ts = ntohl(ping->receiver_ts);
    uint32_t recv_ts = timeval_to_usec(recv_time);
    long rtt = (long)recv_ts - (long)send_ts;

    DEBUG_MSG("Ping from node %hu link %d (%s) rtt %lu", node_id, link_id, 
            ife->network, rtt);
    db_update_pings(gw, ife, rtt);
}

static void remove_stale_links(int link_timeout, int node_timeout)
{
    time_t now = time(0);

    struct gateway *gw;
    struct gateway *tmp_gw;

    HASH_ITER(hh_id, gateway_id_hash, gw, tmp_gw) {
        struct interface *ife;
        struct interface *tmp_ife;

        int num_ifaces = 0;
                
        struct in_addr private_ip;
        ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&private_ip.s_addr);

        DL_FOREACH_SAFE(gw->head_interface, ife, tmp_ife) {
            if((now - ife->last_ping_time) >= link_timeout) {
                if(ife->state == ACTIVE) {
                    ife->state = INACTIVE;
                    gw->active_interfaces--;

                    db_update_link(gw, ife);
                }

                virt_remove_remote_link(&private_ip, &ife->public_ip);
                
                DEBUG_MSG("Removed node %hu link %hu due to timeout",
                        gw->unique_id, ife->index);

                DL_DELETE(gw->head_interface, ife);
                free(ife);
            } else {
                num_ifaces++;
            }
        }

        if(num_ifaces == 0 && (now - gw->last_ping_time) >= node_timeout) {
            gw->state = INACTIVE;
            db_update_gateway(gw, 1);

            virt_remove_remote_node(&private_ip);

            DEBUG_MSG("Removed node %hu due to timeout", gw->unique_id);

            HASH_DELETE(hh_id, gateway_id_hash, gw);
            free(gw);
        }
    }
}

