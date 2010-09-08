#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "contchan.h"
#include "debug.h"
#include "netlink.h"
#include "rootchan.h"
#include "sockets.h"
#include "utlist.h"
#include "virtInterface.h"

const char* WIROOT_ADDRESS = "128.105.22.229";
const unsigned short CCHAN_PORT = 8082;
const unsigned short WIROOT_PORT = 8088;
const int           CLEANUP_INTERVAL = 5; // seconds between calling remove_idle_clients()
const unsigned int  CLIENT_TIMEOUT = 5;

static void server_loop(int cchan_sock);

int main(int argc, char* argv[])
{
    struct lease_info* lease;
    int result;

    DEBUG_MSG("Starting wicontroller...");

    lease = obtain_lease(WIROOT_ADDRESS, WIROOT_PORT);
    if(!lease) {
        DEBUG_MSG("Fatal error: failed to obtain a lease from wiroot server");
//        exit(1);
    }

    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &lease->priv_ip, p_ip, sizeof(p_ip));

    DEBUG_MSG("Obtained lease of %s", p_ip);

    result = setup_virtual_interface(p_ip);
    if(result == -1) {
        DEBUG_MSG("Fatal error: failed to bring up virtual interface");
//        exit(1);
    }

    result = init_interface_list();
    if(result == -1) {
        DEBUG_MSG("Failed to initialize interface list");
    }


    int cchan_sock = tcp_passive_open(CCHAN_PORT, SOMAXCONN);
    if(cchan_sock == -1) {
        DEBUG_MSG("Failed to open control channel socket.");
        exit(1);
    }
    set_nonblock(cchan_sock, 1);

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
            remove_idle_clients(cchan_clients, CLIENT_TIMEOUT);
        } else {
            if(FD_ISSET(cchan_sock, &read_set)) {
                handle_connection(cchan_clients, cchan_sock);
                DEBUG_MSG("client!");
            }

            struct client* client;
            struct client* tmp;

            DL_FOREACH_SAFE(cchan_clients, client, tmp) {
                if(FD_ISSET(client->fd, &read_set)) {
                    handle_disconnection(cchan_clients, client);
                }
            }
        }
    }
}


