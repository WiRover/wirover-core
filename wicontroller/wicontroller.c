#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "configuration.h"
#include "contchan.h"
#include "debug.h"
#include "ping.h"
#include "rootchan.h"
#include "sockets.h"
#include "utlist.h"
#include "kernel.h"
#include "config.h"

const int           CLEANUP_INTERVAL = 5; // seconds between calling remove_idle_clients()
const unsigned int  CLIENT_TIMEOUT = 5;

static void server_loop(int cchan_sock);

int main(int argc, char* argv[])
{
    struct lease_info* lease;
    int result;

    DEBUG_MSG("Starting wicontroller version %d.%d",
              WIROVER_VERSION_MAJOR, WIROVER_VERSION_MINOR);

    const char* wiroot_ip = get_wiroot_ip();
    const unsigned short wiroot_port = get_wiroot_port();
    unsigned short base_port = get_base_port();
    if(!(wiroot_ip && wiroot_port && base_port)) {
        DEBUG_MSG("You must fix the config file.");
        exit(1);
    }

    lease = obtain_lease(wiroot_ip, wiroot_port, base_port);
    if(!lease) {
        DEBUG_MSG("Fatal error: failed to obtain a lease from wiroot server");
//        exit(1);
    }

    char p_ip[INET6_ADDRSTRLEN];
    ipaddr_to_string(&lease->priv_ip, p_ip, sizeof(p_ip));
    DEBUG_MSG("Obtained lease of %s", p_ip);

    result = setup_virtual_interface(p_ip);
    if(result == -1) {
        DEBUG_MSG("Fatal error: failed to bring up virtual interface");
//        exit(1);
    }

    int cchan_sock = tcp_passive_open(base_port + CONTROL_CHANNEL_OFFSET, SOMAXCONN);
    if(cchan_sock == -1) {
        DEBUG_MSG("Failed to open control channel socket.");
        exit(1);
    }
    set_nonblock(cchan_sock, 1);

    if(start_ping_thread() == FAILURE) {
        DEBUG_MSG("Failed to start ping thread");
        exit(1);
    }

#ifdef WITH_KERNEL
    const char* internal_if = get_internal_interface();
    if(kernel_enslave_device(internal_if) == FAILURE) {
        DEBUG_MSG("Failed to enslave device %s", internal_if);
    }
#endif

    server_loop(cchan_sock);

    close(cchan_sock);
    return 0;
}

static void server_loop(int cchan_sock)
{
    int result;
    struct client* cchan_clients = 0;

    while(1) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(cchan_sock, &read_set);

        struct timeval timeout;
        timeout.tv_sec = CLEANUP_INTERVAL;
        timeout.tv_usec = 0;

        int max_fd = cchan_sock;
        fdset_add_clients(cchan_clients, &read_set, &max_fd);

        result = select(max_fd+1, &read_set, 0, 0, &timeout);
        if(result == -1) {
            if(errno != EINTR) {
                ERROR_MSG("select failed");
                return;
            }
        } else if(result == 0) {
            // If select timed out, we must be idle, so it is a good time for
            // cleanup.
            remove_idle_clients(&cchan_clients, CLIENT_TIMEOUT);
        } else {
            if(FD_ISSET(cchan_sock, &read_set)) {
                handle_connection(&cchan_clients, cchan_sock);
            }

            struct client* client;
            struct client* tmp;

            DL_FOREACH_SAFE(cchan_clients, client, tmp) {
                if(FD_ISSET(client->fd, &read_set)) {
                    char buffer[1500];
                    int bytes = recv(client->fd, buffer, sizeof(buffer), 0);
                    if(bytes < 0) {
                        ERROR_MSG("Error receiving from client");
                        handle_disconnection(&cchan_clients, client);
                    } else if(bytes == 0) {
                        handle_disconnection(&cchan_clients, client);
                    } else {
                        process_notification(buffer, bytes);
                    }
                }
            }
        }
    }
}


