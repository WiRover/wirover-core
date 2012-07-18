#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "bandwidth.h"
#include "configuration.h"
#include "contchan.h"
#include "database.h"
#include "debug.h"
#include "ping.h"
#include "rootchan.h"
#include "sockets.h"
#include "utlist.h"
#include "kernel.h"
#include "config.h"

const int           CLEANUP_INTERVAL = 5; // seconds between calling remove_idle_clients()
const unsigned int  CLIENT_TIMEOUT = 5;

static struct bw_server_info bw_server = {
    .timeout = DEFAULT_BANDWIDTH_TIMEOUT,
    .port = DEFAULT_BANDWIDTH_PORT,
};

static void server_loop(int cchan_sock);
static int find_gateway_ip(const char *device, struct in_addr *gw_ip);

int main(int argc, char* argv[])
{
    struct lease_info lease;
    int result;

    printf("WiRover version %d.%d\n", WIROVER_VERSION_MAJOR, WIROVER_VERSION_MINOR);

    const config_t *config = get_config();

    const char* wiroot_address = get_wiroot_address();
    const unsigned short wiroot_port = get_wiroot_port();
    unsigned short data_port = get_data_port();
    unsigned short control_port = get_control_port();
    if(!(wiroot_address && wiroot_port && data_port && control_port)) {
        DEBUG_MSG("You must fix the config file.");
        exit(1);
    }

    result = register_controller(&lease, wiroot_address, wiroot_port, 
            data_port, control_port);
    if(result < 0) {
        DEBUG_MSG("Fatal error: failed to obtain a lease from wiroot server");
        exit(1);
    }

#ifdef WITH_DATABASE
    if(init_database() < 0) {
        DEBUG_MSG("Failed to initialize database connection");
    }
#endif

    uint32_t priv_ip = 0;
    uint32_t priv_netmask = 0;
    char p_ip[INET6_ADDRSTRLEN];

    ipaddr_to_string(&lease.priv_ip, p_ip, sizeof(p_ip));
    DEBUG_MSG("Obtained lease of %s", p_ip);

    ipaddr_to_ipv4(&lease.priv_ip, &priv_ip);
    priv_netmask = htonl(~((1 << lease.priv_subnet_size) - 1));

    result = setup_virtual_interface(priv_ip, priv_netmask, get_mtu());
    if(result == -1) {
        DEBUG_MSG("Fatal error: failed to bring up virtual interface");
    }

    int cchan_sock = tcp_passive_open(control_port, SOMAXCONN);
    if(cchan_sock == -1) {
        DEBUG_MSG("Failed to open control channel socket.");
        exit(1);
    }
    set_nonblock(cchan_sock, 1);

    if(start_ping_thread() == FAILURE) {
        DEBUG_MSG("Failed to start ping thread");
        exit(1);
    }

    if(config) {
        int tmp;
        
        config_lookup_int_compat(config, "bandwidth-server.timeout", &tmp);
        if(tmp > 0)
            bw_server.timeout = tmp;
        else
            DEBUG_MSG("Invalid: bandwidth-server.timeout = %d", tmp);

        config_lookup_int_compat(config, "bandwidth-server.port", &tmp);
        if(tmp > 0 && tmp <= USHRT_MAX)
            bw_server.port = tmp;
        else
            DEBUG_MSG("Invalid: bandwidth-server.port = %d", tmp);
    }

    if(start_bandwidth_server_thread(&bw_server) < 0) {
        DEBUG_MSG("Failed to start bandwidth server thread");
        exit(1);
    }

#ifdef WITH_KERNEL
    const char* internal_if = get_internal_interface();
    if(kernel_enslave_device(internal_if) == FAILURE) {
        DEBUG_MSG("Failed to enslave device %s", internal_if);
    }
    
    struct in_addr gateway_ip;
    if(find_gateway_ip(internal_if, &gateway_ip) == 0) {
        DEBUG_MSG("Found gateway 0x%x for %s", ntohl(gateway_ip.s_addr),
                internal_if);
        virt_set_gateway_ip(internal_if, &gateway_ip);
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
                        process_notification(client->fd, buffer, bytes, bw_server.port);
                    }
                }
            }
        }
    }
}

/*
 * Read the routing table for a default route containing the gateway IP address.
 */
static int find_gateway_ip(const char *device, struct in_addr *gw_ip)
{
    const char *delims = "\t ";

    FILE *file = fopen("/proc/net/route", "r");
    if(!file) {
        ERROR_MSG("Failed to open /proc/net/route");
        return -1;
    }

    char buffer[256];

    // Skip the header line
    fgets(buffer, sizeof(buffer), file);

    char *saveptr = 0;

    while(!feof(file) && fgets(buffer, sizeof(buffer), file)) {
        buffer[sizeof(buffer) - 1] = 0;

        char *dev_str = strtok_r(buffer, delims, &saveptr);
        if(!device)
            continue;

        char *dest = strtok_r(0, delims, &saveptr);
        if(!dest)
            continue;

        char *gateway = strtok_r(0, delims, &saveptr);
        if(!gateway)
            continue;

        uint32_t dest_ip    = (uint32_t)strtoul(dest, 0, 16);
        uint32_t gateway_ip = (uint32_t)strtoul(gateway, 0, 16);

        if(strcmp(device, dev_str) == 0 && dest_ip == 0) {
            gw_ip->s_addr = gateway_ip;
            break;
        }
    }

    fclose(file);
    return 0;
}


