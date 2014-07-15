#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#include "bandwidth.h"
#include "configuration.h"
#include "contchan.h"
#include "constants.h"
#include "database.h"
#include "datapath.h"
#include "debug.h"
#include "pathperf.h"
#include "ping.h"
#include "rootchan.h"
#include "sockets.h"
#include "utlist.h"
#include "config.h"
#include "timing.h"
#include "tunnel.h"

const int           CLEANUP_INTERVAL = 5; // seconds between calling remove_idle_clients()
const unsigned int  CLIENT_TIMEOUT = 5;

static struct bw_server_info bw_server = {
    .start_timeout = DEFAULT_BANDWIDTH_START_TIMEOUT * USECS_PER_SEC,
    .data_timeout = DEFAULT_BANDWIDTH_DATA_TIMEOUT * USECS_PER_SEC,
    .port = DEFAULT_BANDWIDTH_PORT,
    .max_sessions = DEFAULT_BANDWIDTH_MAX_SESSIONS,
};
static unsigned short bw_ext_port = DEFAULT_BANDWIDTH_PORT;

static void server_loop(int cchan_sock);
static int find_gateway_ip(const char *device, struct in_addr *gw_ip);
static int request_lease(const struct lease_info *old_lease, struct lease_info *new_lease);

static struct lease_info lease;
static time_t lease_renewal_time = 0;

int main(int argc, char* argv[])
{
    int result;

    signal(SIGSEGV, segfault_handler);

    printf("WiRover version %d.%d.%d\n", WIROVER_VERSION_MAJOR, 
            WIROVER_VERSION_MINOR, WIROVER_VERSION_REVISION);

    const config_t *config = get_config();

    const char* wiroot_address = get_wiroot_address();
    const unsigned short wiroot_port = get_wiroot_port();
    unsigned short data_port = get_data_port();
    unsigned short control_port = get_control_port();
    if(!(wiroot_address && wiroot_port && data_port && control_port)) {
        DEBUG_MSG("You must fix the config file.");
        exit(1);
    }

    int retry_delay = MIN_LEASE_RETRY_DELAY;
    while(request_lease(NULL, &lease) < 0) {
        DEBUG_MSG("Failed to obtain a lease from root server, will retry in %u seconds",
                retry_delay);
        retry_delay = exp_delay(retry_delay, MIN_LEASE_RETRY_DELAY, MAX_LEASE_RETRY_DELAY);
    }
    lease_renewal_time = time(NULL) + lease.time_limit - RENEW_BEFORE_EXPIRATION;

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
    priv_netmask = htonl(slash_to_netmask(lease.priv_subnet_size));

    result = tunnel_create(priv_ip, priv_netmask, get_mtu());
    if(result == -1) {
        DEBUG_MSG("Fatal error: failed to bring up tunnel interface");
    }

    int cchan_sock = tcp_passive_open(control_port, SOMAXCONN);
    if(cchan_sock == -1) {
        DEBUG_MSG("Failed to open control channel socket.");
        exit(1);
    }
    set_nonblock(cchan_sock, 1);

    if(start_data_thread(getTunnel()) == FAILURE) {
        DEBUG_MSG("Failed to start data thread");
        exit(1);
    }

    if(start_ping_thread() == FAILURE) {
        DEBUG_MSG("Failed to start ping thread");
        exit(1);
    }

    if(config) {
        int tmp = 0;
        int found = 0;

        // Set a maximum because we are going to convert to microseconds.
        int max_timeout = (UINT_MAX / USECS_PER_SEC);

        found = config_lookup_int_compat(config, "bandwidth-port", &tmp);
        if(found == CONFIG_TRUE) {
            if(tmp > 0 && tmp <= USHRT_MAX) {
                bw_server.port = tmp;
            } else {
                DEBUG_MSG("Invalid value for bandwidth-port (%d): must be positive and at most %hu", 
                        tmp, USHRT_MAX);
            }
        }

        found = config_lookup_int_compat(config, "bandwidth-start-timeout", &tmp);
        if(found == CONFIG_TRUE) {
            if(tmp > 0 && tmp <= max_timeout) {
                bw_server.start_timeout = tmp * USECS_PER_SEC;
            } else {
                DEBUG_MSG("Invalid value for bandwidth-start-timeout (%d): must be positive and at most %d",
                        tmp, max_timeout);
            }
        }

        found = config_lookup_int_compat(config, "bandwidth-data-timeout", &tmp);
        if(found == CONFIG_TRUE) {
            if(tmp > 0 && tmp <= max_timeout) {
                bw_server.data_timeout = tmp * USECS_PER_SEC;
            } else {
                DEBUG_MSG("Invalid value for bandwidth-data-timeout (%d): must be positive and at most %d",
                        tmp, max_timeout);
            }
        }

        found = config_lookup_int_compat(config, "bandwidth-max-sessions", &tmp);
        if(found == CONFIG_TRUE) {
            if(tmp > 0) {
                bw_server.max_sessions = tmp;
            } else {
                DEBUG_MSG("Invalid value for bandwidth-max-sessions (%d): must be positive", tmp);
            }
        }

        bw_ext_port = get_register_bandwidth_port();
        if(!bw_ext_port)
            bw_ext_port = bw_server.port;
    }

    if(start_bandwidth_server_thread(&bw_server) < 0) {
        DEBUG_MSG("Failed to start bandwidth server thread");
        exit(1);
    }

    start_path_perf_thread();

    server_loop(cchan_sock);

    close(cchan_sock);
    return 0;
}

static void server_loop(int cchan_sock)
{
    int result;
    struct client* cchan_clients = 0;
    int lease_retry_delay = MIN_LEASE_RETRY_DELAY;

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
                DEBUG_MSG("Handled accept connection");
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
                        process_notification(client->fd, buffer, bytes, bw_ext_port);
                    }
                }
            }
        }

        if(time(NULL) >= lease_renewal_time) {
            struct lease_info new_lease;
            if(request_lease(&lease, &new_lease) == 0) {
                memcpy(&lease, &new_lease, sizeof(lease));
                lease_renewal_time = time(NULL) + new_lease.time_limit - 
                    RENEW_BEFORE_EXPIRATION;
                lease_retry_delay = MIN_LEASE_RETRY_DELAY;
            } else {
                DEBUG_MSG("Lease renewal failed, will retry in %u seconds",
                        lease_retry_delay);
                lease_renewal_time = time(NULL) + lease_retry_delay;
                lease_retry_delay = exp_inc(lease_retry_delay, 
                        MIN_LEASE_RETRY_DELAY, MAX_LEASE_RETRY_DELAY);
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

/*
 * Request a lease from root server.  If successful, the new lease is stored in
 * new_lease.  
 *
 * If old_lease is null or new_lease differs from old_lease (eg. received a
 * different IP address), this function will make the appropriate system
 * changes.
 *
 * Return 0 on success or a negative value on failure.
 */
static int request_lease(const struct lease_info *old_lease, struct lease_info *new_lease)
{
    const char* wiroot_address = get_wiroot_address();
    const unsigned short wiroot_port = get_wiroot_port();

    // reg_data_port and reg_control_port are the ports we will advertise to
    // the root server.  They may differ from the ports we listen on if we are
    // behind a DNAT.
    unsigned short reg_data_port = get_register_data_port();
    if(!reg_data_port)
        reg_data_port = get_data_port();

    unsigned short reg_control_port = get_register_control_port();
    if(!reg_control_port)
        reg_control_port = get_control_port();

    int result = register_controller(new_lease, wiroot_address, wiroot_port, 
            reg_data_port, reg_control_port);
    if(result == 0) {
        if(new_lease->unique_id == 0) {
            DEBUG_MSG("Lease request rejected");
            return -1;
        }

        char my_ip[INET6_ADDRSTRLEN];
        ipaddr_to_string(&new_lease->priv_ip, my_ip, sizeof(my_ip));

        if(!old_lease || ipaddr_cmp(&new_lease->priv_ip, &old_lease->priv_ip) != 0 ||
                new_lease->priv_subnet_size != old_lease->priv_subnet_size) {
            DEBUG_MSG("Obtained lease of %s/%hhu",
                    my_ip, new_lease->priv_subnet_size);

            uint32_t priv_ip;
            ipaddr_to_ipv4(&new_lease->priv_ip, &priv_ip);
    
            uint32_t priv_netmask = htonl(slash_to_netmask(new_lease->priv_subnet_size));
            

        }

        return 0;
    } else {
        return -1;
    }
}


