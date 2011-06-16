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
#include "utlist.h"

static void* ping_thread_func(void* arg);
static int handle_incoming(int sockfd);

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
    const unsigned short    base_port = get_base_port();
    int sockfd;

    sockfd = udp_bind_open(base_port, 0);
    if(sockfd == FAILURE) {
        DEBUG_MSG("Ping thread cannot continue due to failure");
        return 0;
    }

    // We never want reads to hold up the thread.
    set_nonblock(sockfd, NONBLOCKING);

    while(1) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        int result = select(sockfd+1, &read_set, 0, 0, 0);
        if(result > 0 && FD_ISSET(sockfd, &read_set)) {
            // Most likely we have an incoming ping request.
            handle_incoming(sockfd);
        } else if(result < 0) {
            ERROR_MSG("select failed for ping socket (%d)", sockfd);
        }
    }

    close(sockfd);
    running = 0;
    return 0;
}

static int handle_incoming(int sockfd)
{
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    char buffer[1024];

    int bytes_recvd = recvfrom(sockfd, buffer, sizeof(buffer), 0,
            (struct sockaddr*)&from, &from_len);
    if(bytes_recvd < 0) {
        ERROR_MSG("recvfrom failed (socket %d)", sockfd);
        return -1;
    }

    int bytes_sent = sendto(sockfd, buffer, bytes_recvd, 0,
            (struct sockaddr*)&from, from_len);
    if(bytes_sent < 0) {
        ERROR_MSG("Failed to send ping response (socket %d)", sockfd);
    }

    if(bytes_recvd < PING_PACKET_SIZE)
        return 0;

    struct ping_packet *ping = (struct ping_packet *)
        (buffer + sizeof(struct tunhdr));

    unsigned short node_id = ntohs(ping->src_id);
    if(node_id == 0)
        return 0;

    struct gateway *gw = lookup_gateway_by_id(node_id);
    if(!gw)
        return 0;

    /* It is important to verify the identity of the ping sender.  Without this
     * check, a malicious user could send a fake ping packet that would cause
     * traffic to be redirected to the source address of the ping. */
    if(gw->secret_word != ntohl(ping->secret_word)) {
        DEBUG_MSG("Secret word mismatch for node %hu", node_id);
        DEBUG_MSG("This may be due to a race condition or an imposter.");
        return 0;
    }

    unsigned link_id = ntohl(ping->link_id);
    struct interface *ife = 
        find_interface_by_index(gw->head_interface, link_id);

    // TODO: Add IPv6 support
    struct sockaddr_in from_in;
    if(sockaddr_to_sockaddr_in((struct sockaddr *)&from, from_len, &from_in) < 0) {
        char p_ip[INET6_ADDRSTRLEN];
        getnameinfo((struct sockaddr *)&from, from_len, p_ip, sizeof(p_ip), 
                0, 0, NI_NUMERICHOST);

        DEBUG_MSG("Unable to add interface with address %s (IPv6?)", p_ip);
        return 0;
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
        }
    } else {
        /* The main reason for adding missing links on ping packets is if
         * the controller is restarted (the list of links is cleared).  A more
         * 
         * TODO: Instead, write state to a file on exit and read the file
         * on start up. */
        ife = alloc_interface();
        if(!ife) {
            DEBUG_MSG("out of memory");
            return 0;
        }

        // TODO: add interface name, and network name
        memcpy(&ife->public_ip, &from_in.sin_addr, sizeof(struct in_addr));
        ife->data_port = from_in.sin_port;
        ife->state     = ping->link_state;
        ife->index     = ntohl(ping->link_id);

        DL_APPEND(gw->head_interface, ife);

        if(ife->state == ACTIVE) {
            struct in_addr private_ip;
            ipaddr_to_ipv4(&gw->private_ip, (uint32_t *)&private_ip.s_addr);

            gw->active_interfaces++;
            virt_add_remote_link(&private_ip, &from_in.sin_addr, 
                    from_in.sin_port);
        }
    }

    return 0;
}

