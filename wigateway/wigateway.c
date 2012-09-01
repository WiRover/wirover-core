#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "arguments.h"
#include "bandwidth.h"
#include "config.h"
#include "configuration.h"
#include "contchan.h"
#include "debug.h"
#include "gps_handler.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "kernel.h"
#include "callback.h"
#include "sockets.h"

// The virtual interface will use this IP address if we are unable to obtain a
// private IP from the root server.
#define DEFAULT_VIRT_ADDRESS    "172.31.25.1"
#define DEFAULT_NETMASK         "255.255.255.0"
#define VIRT_DEVICE             "virt0"
#define RETRY_DELAY             5
#define NODE_ID_FILE            "/var/lib/wirover/node_id"

enum {
    GATEWAY_START,
    GATEWAY_LEASE_OBTAINED,
    GATEWAY_PING_SUCCEEDED,
    GATEWAY_NOTIFICATION_SUCCEEDED,
};

static int write_node_id_file(int node_id);
static int renew_lease(const struct lease_info *old_lease, struct lease_info *new_lease);

static time_t lease_renewal_time = 0;

int main(int argc, char* argv[])
{
    int result;

    signal(SIGSEGV, segfault_handler);

    printf("WiRover version %d.%d.%d\n", WIROVER_VERSION_MAJOR, 
            WIROVER_VERSION_MINOR, WIROVER_VERSION_REVISION);

    srand(time(0));

    if(parse_arguments(argc, argv) < 0)
        exit(1);

    const char* wiroot_address = get_wiroot_address();
    const unsigned short wiroot_port = get_wiroot_port();
    unsigned short data_port = get_data_port();
    if(!(wiroot_address && wiroot_port && data_port)) {
        exit(1);
    } 
            
    if(create_netlink_thread() == -1) {
        DEBUG_MSG("Failed to create netlink thread");
        exit(1);
    }

    if(init_interface_list() == -1) {
        DEBUG_MSG("Failed to initialize interface list");
        exit(1);
    }

    if(init_gps_handler() == -1) {
        DEBUG_MSG("Failed to initialize gps handler");
    }

    uint32_t private_ip = 0;
    inet_pton(AF_INET, DEFAULT_VIRT_ADDRESS, &private_ip);

    uint32_t private_netmask = 0;
    inet_pton(AF_INET, DEFAULT_NETMASK, &private_netmask);

    int state = GATEWAY_START;
    struct lease_info lease;

    // Generate our private key
    if(RAND_bytes(private_key, sizeof(private_key)) != 1) {
        DEBUG_MSG("RAND_bytes failed, falling back to RAND_pseudo_bytes");

        if(RAND_pseudo_bytes(private_key, sizeof(private_key)) != 1) {
            DEBUG_MSG("RAND_pseudo_bytes failed");
            exit(1);
        }
    }

    while(1) {
        if(state == GATEWAY_START) {
            result = register_gateway(&lease, wiroot_address, wiroot_port);
            if(result == 0) {
                if(lease.unique_id == 0) {
                    DEBUG_MSG("Lease request rejected, will retry in %u seconds",
                            LEASE_RETRY_DELAY);
                    sleep(LEASE_RETRY_DELAY);
                    continue;
                }

                if(lease.controllers <= 0) {
                    DEBUG_MSG("Could not find any controllers, will retry in %u seconds",
                            LEASE_RETRY_DELAY);
                    sleep(LEASE_RETRY_DELAY);
                    continue;
                }

                char my_ip[INET6_ADDRSTRLEN];
                ipaddr_to_string(&lease.priv_ip, my_ip, sizeof(my_ip));
                DEBUG_MSG("Obtained lease of %s and unique id %u", my_ip, lease.unique_id);
                DEBUG_MSG("There are %d controllers available.", lease.controllers);

                write_node_id_file(lease.unique_id);
                call_on_lease(lease.unique_id);

                ipaddr_to_ipv4(&lease.priv_ip, &private_ip);
                private_netmask = htonl(slash_to_netmask(lease.priv_subnet_size));
                
                lease_renewal_time = time(NULL) + lease.time_limit -
                    RENEW_BEFORE_EXPIRATION;
                
                if(ARGS.with_kernel) {
                    result = setup_virtual_interface(private_ip, 
                            private_netmask, get_mtu());
                    if(result == -1) {
                        DEBUG_MSG("Failed to bring up virtual interface");
                        exit(1);
                    }
                }

                char cont_ip[INET6_ADDRSTRLEN];
                ipaddr_to_string(&lease.cinfo[0].pub_ip, cont_ip, sizeof(cont_ip));
                DEBUG_MSG("First controller is at: %s", cont_ip);

                if(ARGS.with_kernel) {
                    uint32_t priv_ip;
                    uint32_t pub_ip;

                    ipaddr_to_ipv4(&lease.cinfo[0].priv_ip, &priv_ip);
                    ipaddr_to_ipv4(&lease.cinfo[0].pub_ip, &pub_ip);

                    virt_add_remote_node((struct in_addr *)&priv_ip);
                    virt_add_remote_link((struct in_addr *)&priv_ip, 
                        (struct in_addr *)&pub_ip, lease.cinfo[0].data_port);
                
                    // Add a default vroute that directs all traffic to the controller
                    virt_add_vroute(0, 0, priv_ip);
                }

                if(start_ping_thread() == FAILURE) {
                    DEBUG_MSG("Failed to start ping thread");
                    exit(1);
                }
                
                state = GATEWAY_LEASE_OBTAINED;
            }
        } else if(time(NULL) >= lease_renewal_time) {
            struct lease_info new_lease;
            if(renew_lease(&lease, &new_lease) == 0) {
                memcpy(&lease, &new_lease, sizeof(lease));
                lease_renewal_time = time(NULL) + lease.time_limit -
                    RENEW_BEFORE_EXPIRATION;
            } else {
                DEBUG_MSG("Lease renewal failed, will retry in %u seconds",
                        LEASE_RETRY_DELAY);
                sleep(LEASE_RETRY_DELAY);
                continue;
            }
        }

        if(state == GATEWAY_LEASE_OBTAINED) {
            if(find_active_interface(interface_list)) {
                if(ARGS.with_kernel) {
                    result = add_route(0, 0, 0, VIRT_DEVICE);

                    // EEXIST means the route was already present -> not a failure
                    if(result < 0 && result != -EEXIST) {
                        DEBUG_MSG("add_route failed");
                        exit(1);
                    }
                }
                
                state = GATEWAY_PING_SUCCEEDED;
            }
        }

        if(state == GATEWAY_PING_SUCCEEDED) {
            if(send_notification(1) == 0) {
                // TODO: Set default policy to encap

                state = GATEWAY_NOTIFICATION_SUCCEEDED;
                
                uint32_t pub_ip;
                ipaddr_to_ipv4(&lease.cinfo[0].pub_ip, &pub_ip);

                struct bw_client_info bw_client;
                memset(&bw_client, 0, sizeof(bw_client));
                bw_client.timeout = DEFAULT_BANDWIDTH_TIMEOUT;
                bw_client.remote_addr = pub_ip;
                bw_client.remote_port = get_remote_bw_port();
                bw_client.interval = USEC_PER_SEC * get_bandwidth_test_interval();

                if(start_bandwidth_client_thread(&bw_client) < 0) {
                    DEBUG_MSG("Failed to start bandwidth client thread");
                    exit(1);
                }
            }
        }

        sleep(RETRY_DELAY);
    }

    return 0;
}

/*
 * Write the node_id to a known file so that other utilities may make use of it.
 */
static int write_node_id_file(int node_id)
{
    FILE *file = fopen(NODE_ID_FILE, "w");
    if(!file) {
        ERROR_MSG("Failed to open %s for writing", NODE_ID_FILE);
        return -1;
    }

    fprintf(file, "%d", node_id);

    fclose(file);
    return 0;
}

/*
 * Attempt to renew lease with root server.  If successful, the new lease is
 * stored in new_lease.  If new_lease differs from old_lease (eg. received a
 * different IP address), this function will make the appropriate changes.
 *
 * Return 0 on success or a negative value on failure.
 */
static int renew_lease(const struct lease_info *old_lease, struct lease_info *new_lease)
{
    const char* wiroot_address = get_wiroot_address();
    const unsigned short wiroot_port = get_wiroot_port();

    int result = register_gateway(new_lease, wiroot_address, wiroot_port);
    if(result == 0) {
        char my_ip[INET6_ADDRSTRLEN];
        ipaddr_to_string(&new_lease->priv_ip, my_ip, sizeof(my_ip));

        if(new_lease->unique_id == 0) {
            DEBUG_MSG("Lease renewal rejected");
            return -1;
        }

        if(ipaddr_cmp(&new_lease->priv_ip, &old_lease->priv_ip) != 0 ||
                new_lease->priv_subnet_size != old_lease->priv_subnet_size) {
            DEBUG_MSG("Obtained lease of %s/%hhu", 
                    my_ip, new_lease->priv_subnet_size);

            if(ARGS.with_kernel) {
                uint32_t private_ip;
                ipaddr_to_ipv4(&new_lease->priv_ip, &private_ip);
                
                uint32_t private_netmask = htonl(slash_to_netmask(new_lease->priv_subnet_size));
            
                result = setup_virtual_interface(private_ip, private_netmask, get_mtu());
                if(result == -1) {
                    DEBUG_MSG("Failed to bring up virtual interface");
                    exit(1);
                }
            }
        } else {
            DEBUG_MSG("Renewed lease of %s/%hhu", 
                    my_ip, new_lease->priv_subnet_size);
        }
        
        if(new_lease->unique_id != old_lease->unique_id) {
            DEBUG_MSG("Changing unique_id from %u to %u\n");
            write_node_id_file(new_lease->unique_id);
            call_on_lease(new_lease->unique_id);
        }

        /* TODO: Handle potential change of controller */

        return 0;
    } else {
        return -1;
    }
}

