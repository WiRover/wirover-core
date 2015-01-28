#define _BSD_SOURCE /* required for be64toh */

#include <libconfig.h>
//#include <stropts.h>
#include <unistd.h>
#include <asm-generic/sockios.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <endian.h>
#include <arpa/inet.h>

#include "config.h"
#include "configuration.h"
#include "database.h"
#include "datapath.h"
#include "debug.h"
#include "remote_node.h"
#include "interface.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "select_interface.h"
#include "sockets.h"
#include "timing.h"
#include "tunnel.h"
#include "uthash.h"
#include "utlist.h"

static void* ping_thread_func(void* arg);
static int ping_request_valid(char *buffer, int len);
static int send_response(struct interface *local_ife, const struct remote_node *gw,
                         unsigned char type, struct sockaddr_storage *from, char *buffer, int len, float bw);
static void process_ping_request(char *buffer, int len, 
                                 const struct sockaddr *from, socklen_t from_len);
static void process_ping_response(char *buffer, int len, 
                                  const struct sockaddr *from, socklen_t from_len,
                                  const struct timeval *recv_time);
static void process_ping_payload(char *buffer, int len,
struct remote_node *gw, struct interface *ife);
static void remove_stale_links(int link_timeout, int node_timeout);

static int          running;
static pthread_t    ping_thread;

static int error_responses = 0;
static time_t last_error_response = 0;
static int mtu = 0;

int start_ping_thread()
{
    mtu = get_mtu();
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
    int link_timeout = get_link_timeout();
    int node_timeout = DEFAULT_NODE_TIMEOUT;
    int sleep_time = link_timeout;;

    const config_t *config = get_config();
    if(config) {
        config_lookup_int_compat(config, "node-timeout", &node_timeout);
        if(node_timeout <= 0) {
            DEBUG_MSG("Invalid value for node-timeout (%d)", node_timeout);
            node_timeout = DEFAULT_NODE_TIMEOUT;
        }
    }
    if(node_timeout < sleep_time) { sleep_time = node_timeout; }

    while(1) {
        remove_stale_links(link_timeout, node_timeout);
        sleep(sleep_time);
    }
    running = 0;
    return 0;
}

int handle_incoming_ping(struct sockaddr_storage *from_addr, struct timeval recv_time, struct interface *local_ife,
struct interface *remote_ife, char *buffer, int bytes_recvd)
{
    int sockfd = local_ife->sockfd;
    int from_len = sizeof(struct sockaddr_storage);
    int valid = ping_request_valid(buffer, bytes_recvd);
    if(sockfd <= 0) {
        DEBUG_MSG("Tried to handle incoming ping on bad sockfd");
        return FAILURE;
    }
    if(valid != PING_ERR_OK) {
        char src_addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in *)from_addr)->sin_addr, src_addr, sizeof(src_addr));

        unsigned short src_port = sockaddr_port((struct sockaddr *)from_addr);

        DEBUG_MSG("Packet from %s:%hu produced error: %s", src_addr, src_port, 
            ping_err_str(valid));

        time_t now = time(NULL);
        if(now != last_error_response)
            error_responses = 0;

        if(error_responses < ERROR_RESPONSE_LIMIT) {
            DEBUG_MSG("Sending error response");
            if(send_response(local_ife, NULL, PING_RESPONSE_ERROR,  from_addr,
                buffer, bytes_recvd, 0) < 0) {
                    ERROR_MSG("Failed to send error response");
            }
            error_responses++;
            last_error_response = now;
        }

        return 0;
    }
    const struct ping_packet *ping = (struct ping_packet *)(buffer);
    unsigned short node_id = ntohs(ping->src_id);

    struct remote_node *gw = lookup_remote_node_by_id(node_id);
    long time_diff = timeval_diff(&recv_time, &remote_ife->last_ping_time);
    float bw = bytes_recvd * 1.0f / time_diff;

    switch(PING_TYPE(ping->type)) {
    case PING_REQUEST:
        remote_ife->last_ping_time = recv_time;

        process_ping_request(buffer, bytes_recvd, 
            (struct sockaddr *)from_addr, from_len);

        if(send_response(local_ife, gw, PING_RESPONSE, from_addr,
            buffer, bytes_recvd, bw) < 0) {
                ERROR_MSG("Failed to send ping response");
                return 0;
        }
        break;
    case PING_SECOND_RESPONSE:
        process_ping_response(buffer, bytes_recvd,
            (struct sockaddr *)from_addr, from_len, &recv_time);

        break;
    }

    return 0;
}

/*
* Do minimal preprocessing to determine the type of ping packet
* and whether it is valid or not.
*
* Returns one of the error codes:
*  PING_ERR_OK
*  PING_ERR_TOO_SHORT
*  PING_ERR_BAD_NODE
*  PING_ERR_BAD_LINK
*  PING_ERR_BAD_HASH
*  PING_ERR_NOT_PING
*  PING_ERR_BAD_TYPE
*/
static int ping_request_valid(char *buffer, int len)
{
    if(len < MIN_PING_PACKET_SIZE)
        return PING_ERR_TOO_SHORT;

    struct ping_packet *ping = (struct ping_packet *)(buffer);
    switch(PING_TYPE(ping->type)) {
    case PING_REQUEST:
    case PING_SECOND_RESPONSE:
    case PING_TAILGATE:
        break;
    default:
        return PING_ERR_BAD_TYPE;
    }

    /* node_id == 0 is invalid, remote_node should have received a non-zero id from
    * the root server. */
    unsigned short node_id = ntohs(ping->src_id);
    if(node_id == 0)
        return PING_ERR_BAD_NODE;

    struct remote_node *gw = lookup_remote_node_by_id(node_id);

    if(gw) {
        if(verify_ping_sender(ping, buffer, 
            len, gw->private_key) == 0) {
                unsigned link_id = ntohl(ping->link_id);

                struct interface *ife = 
                    find_interface_by_index(gw->head_interface, link_id);

                if(!ife) {
                    DEBUG_MSG("Unrecognized interface (%u) for node (%hu)", 
                        link_id, node_id);
                    return PING_ERR_BAD_LINK;
                }
        } else {
            DEBUG_MSG("SHA hash mismatch");
            return PING_ERR_BAD_HASH;
        }
    } else {
        DEBUG_MSG("Unrecognized remote_node (%hu)", node_id);
        return PING_ERR_BAD_NODE;
    }

    return PING_ERR_OK;
}

/*
* Send a ping response.
*
* Assumes the buffer is at least MIN_PING_PACKET_SIZE in length.
*/
static int send_response(struct interface *local_ife, const struct remote_node *gw,
                         unsigned char type, struct sockaddr_storage *from, char *buffer, int len, float bw)
{
    char response_buffer[mtu];

    if(len < sizeof(response_buffer)) {
        memset(response_buffer, 0, sizeof(response_buffer));
        memcpy(response_buffer, buffer, len);
    } else {
        memcpy(response_buffer, buffer, sizeof(response_buffer));
    }

    struct ping_packet *ping = (struct ping_packet *)(response_buffer);

    ping->type = type;
    ping->src_id = htons(get_unique_id());
    ping->receiver_ts = htonl(timeval_to_usec(0));
    ping->est_bw = htonl(bw_to_int(bw));

    if(gw) {
        fill_ping_digest(ping, response_buffer, MIN_PING_PACKET_SIZE, gw->private_key);
    } else {
        memset(ping->digest, 0, sizeof(ping->digest));
    }
    return send_encap_packet_dst_noinfo(TUNTYPE_PING, response_buffer, MIN_PING_PACKET_SIZE, interface_list, from);
}

/*
* Use the ping packet to update the list of links for a remote_node.  If the link
* is absent in our list, we can add it as an active interface, or if the link
* was present but with a different IP address, we can update it.  The latter
* case is especially relevent when the remote_node is behind a NAT.
*/
static void process_ping_request(char *buffer, int len, 
                                 const struct sockaddr *from, socklen_t from_len)
{
    struct ping_packet *ping = (struct ping_packet *)
        (buffer);

    unsigned short node_id = ntohs(ping->src_id);

    struct remote_node *gw = lookup_remote_node_by_id(node_id);
    if(!gw)
        return;

    gw->last_ping_time = time(0);

    unsigned link_id = ntohl(ping->link_id);
    struct interface *ife = 
        find_interface_by_index(gw->head_interface, link_id);

    if(!ife) {
        DEBUG_MSG("Error: interface not recognized");
        return;
    }

    // TODO: Add IPv6 support
    struct sockaddr_in from_in;

    if(sockaddr_to_sockaddr_in(from, sizeof(struct sockaddr), &from_in) < 0) {
        char p_ip[INET6_ADDRSTRLEN];
        getnameinfo(from, from_len, p_ip, sizeof(p_ip), 0, 0, NI_NUMERICHOST);

        DEBUG_MSG("Unable to add interface with address %s (IPv6?)", p_ip);
        return;
    }

    /* The main reason for this check is if the remote_node is behind a NAT,
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

            memcpy(&ife->public_ip, &from_in.sin_addr, sizeof(struct in_addr));
            ife->data_port  = from_in.sin_port;
            ife->state      = ping->link_state;

            /* We now know that ife->public_ip and ife->data_port are correct. */
            ife->flags |= IFFLAG_SOURCE_VERIFIED;

#ifdef WITH_DATABASE
            db_update_link(gw, ife);
#endif
    } else if((ife->flags & IFFLAG_SOURCE_VERIFIED) == 0) {
        /* The source was correct, but now we can say it has been verified. */
        ife->flags |= IFFLAG_SOURCE_VERIFIED;

        if(ife->state == ACTIVE) {
            struct in_addr private_ip;
            ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&private_ip.s_addr);
        }
    }

    process_ping_payload(buffer, len, gw, ife);
}

/*
* Use the ping response do determine link RTT.
*/
static void process_ping_response(char *buffer, int len, 
                                  const struct sockaddr *from, socklen_t from_len,
                                  const struct timeval *recv_time)
{


    struct ping_packet *ping = (struct ping_packet *)(buffer);

    unsigned short node_id = ntohs(ping->src_id);

    struct remote_node *gw = lookup_remote_node_by_id(node_id);
    if(!gw)
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

    ife->avg_rtt = ewma_update(ife->avg_rtt, (double)rtt, RTT_EWMA_WEIGHT);

    DEBUG_MSG("Ping from node %hu link %d (%s) rtt %lu avg_rtt %.0f",
        node_id, link_id, ife->network, rtt, ife->avg_rtt);

    if(ife->state == INACTIVE) {
        DEBUG_MSG("Marking node %hu link %d (%s) ACTIVE",
            node_id, link_id, ife->network);

        ife->state = ACTIVE;
        gw->active_interfaces++;

        // TODO: Add IPv6 support
        /*struct sockaddr_in from_in;
        if(sockaddr_to_sockaddr_in(from, from_len, &from_in) < 0) {
        char p_ip[INET6_ADDRSTRLEN];
        getnameinfo(from, from_len, p_ip, sizeof(p_ip), 0, 0, NI_NUMERICHOST);

        DEBUG_MSG("Unable to add interface with address %s (IPv6?)", p_ip);
        return;
        }*/
    }

    db_update_pings(gw, ife, rtt);
    db_update_link(gw, ife);

    process_ping_payload(buffer, len, gw, ife);
}

static void process_ping_payload(char *buffer, int len, 
struct remote_node *gw, struct interface *ife)
{
    int curr_payload_size = sizeof(struct ping_packet);
    int next_type = PING_NEXT(buffer[0]);

    while(next_type != PING_NO_PAYLOAD && len > curr_payload_size) {
        buffer += curr_payload_size;
        len    -= curr_payload_size;

        switch(next_type) {
        case PING_GPS_PAYLOAD:
            if(len >= sizeof(struct gps_payload)) {
                struct gps_payload *gps = (struct gps_payload *)buffer;

                DEBUG_MSG("Node %hu gps %f, %f", gw->unique_id,
                    gps->latitude, gps->longitude);

                db_update_gps(gw, gps);
            }

            curr_payload_size = sizeof(struct gps_payload);
            break;

        case PING_PASSIVE_PAYLOAD:
            if(len >= sizeof(struct passive_payload)) {
                struct passive_payload *passive = (struct passive_payload *)buffer;

                DEBUG_MSG("Node %hu network %s tx %llu rx %llu",
                    gw->unique_id, ife->network,
                    be64toh(passive->bytes_tx),
                    be64toh(passive->bytes_rx));

                db_update_passive(gw, ife, passive);
            }

            curr_payload_size = sizeof(struct passive_payload);
            break;
        }

        next_type = PING_TYPE(buffer[0]);
    }
}

static void remove_stale_links(int link_timeout, int node_timeout)
{
    time_t now = time(0);

    struct remote_node *gw;
    struct remote_node *tmp_gw;
    obtain_write_lock(&remote_node_lock);
    HASH_ITER(hh_id, remote_node_id_hash, gw, tmp_gw) {

        if((now - gw->last_ping_time) >= node_timeout) {

            DEBUG_MSG("Removed node %hu due to timeout", gw->unique_id);

            remove_remote_node(gw);
        }
    }
    release_write_lock(&remote_node_lock);
}

