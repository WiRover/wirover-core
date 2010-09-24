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
#include "debug.h"
#include "interface.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"

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

    sockfd = udp_bind_open(base_port);
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
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[1024];

    int bytes_recvd = recvfrom(sockfd, buffer, sizeof(buffer), 0,
            (struct sockaddr*)&addr, &addr_len);
    if(bytes_recvd < 0) {
        ERROR_MSG("recvfrom failed (socket %d)", sockfd);
    } else if(bytes_recvd >= sizeof(struct ping_packet)) {
        //struct ping_packet* pkt = (struct ping_packet*)buffer;

        int bytes_sent = sendto(sockfd, buffer, bytes_recvd, 0,
                (struct sockaddr*)&addr, addr_len);
        if(bytes_sent < 0) {
            ERROR_MSG("Failed to send ping response (socket %d)", sockfd);
        }
    }

    return 0;
}

