#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include "configuration.h"
#include "contchan.h"
#include "debug.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "kernel.h"

// The virtual interface will use this IP address if we are unable to obtain a
// private IP from the root server.
#define DEFAULT_VIRT_ADDRESS    "172.31.25.1"
#define DEFAULT_NETMASK         "255.255.255.0"

#define VIRT_DEVICE             "virt0"

#define RETRY_DELAY             5

enum {
    GATEWAY_START,
    GATEWAY_LEASE_OBTAINED,
    GATEWAY_PING_SUCCEEDED,
    GATEWAY_NOTIFICATION_SUCCEEDED,
};

int main(int argc, char* argv[])
{
    int result;

    srand(time(0));

    const char* wiroot_ip = get_wiroot_ip();
    const unsigned short wiroot_port = get_wiroot_port();
    unsigned short base_port = get_base_port();
    if(!(wiroot_ip && wiroot_port && base_port)) {
        DEBUG_MSG("You must fix the config file.");
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

    uint32_t private_ip = 0;
    inet_pton(AF_INET, DEFAULT_VIRT_ADDRESS, &private_ip);

    uint32_t private_netmask = 0;
    inet_pton(AF_INET, DEFAULT_NETMASK, &private_netmask);

    int state = GATEWAY_START;
    const struct lease_info *lease = 0;

    while(1) {
        if(state == GATEWAY_START) {
            lease = obtain_lease(wiroot_ip, wiroot_port, base_port);
            if(lease) {
                char my_ip[INET6_ADDRSTRLEN];
                ipaddr_to_string(&lease->priv_ip, my_ip, sizeof(my_ip));
                DEBUG_MSG("Obtained lease of %s and unique id %u", my_ip, lease->unique_id);
                DEBUG_MSG("There are %d controllers available.", lease->controllers);

                ipaddr_to_ipv4(&lease->priv_ip, &private_ip);
                private_netmask = htonl(~((1 << lease->priv_subnet_size) - 1));
                
                result = setup_virtual_interface(private_ip, private_netmask);
                if(result == -1) {
                    DEBUG_MSG("Failed to bring up virtual interface");
                    exit(1);
                }

                if(lease->controllers > 0) {
                    char cont_ip[INET6_ADDRSTRLEN];
                    ipaddr_to_string(&lease->cinfo[0].pub_ip, cont_ip, sizeof(cont_ip));
                    DEBUG_MSG("First controller is at: %s", cont_ip);

                    uint32_t priv_ip;
                    uint32_t pub_ip;

                    ipaddr_to_ipv4(&lease->cinfo[0].priv_ip, &priv_ip);
                    ipaddr_to_ipv4(&lease->cinfo[0].pub_ip, &pub_ip);

                    virt_add_remote_node((struct in_addr *)&priv_ip);
                    virt_add_remote_link((struct in_addr *)&priv_ip, 
                        (struct in_addr *)&pub_ip, lease->cinfo[0].base_port);
                
                    // Add a default vroute that directs all traffic to the controller
                    virt_add_vroute(0, 0, priv_ip);

                    if(start_ping_thread() == FAILURE) {
                        DEBUG_MSG("Failed to start ping thread");
                        exit(1);
                    }
                } else {
                    DEBUG_MSG("Cannot continue without a controller");
                    exit(1);
                }
                
                state = GATEWAY_LEASE_OBTAINED;
            }
        }

        if(state == GATEWAY_LEASE_OBTAINED) {
            if(find_active_interface(interface_list)) {
                result = add_route(0, 0, 0, VIRT_DEVICE);

                // EEXIST means the route was already present -> not a failure
                if(result < 0 && result != -EEXIST) {
                    DEBUG_MSG("add_route failed");
                    exit(1);
                }
                
                state = GATEWAY_PING_SUCCEEDED;
            }
        }

        if(state == GATEWAY_PING_SUCCEEDED) {
            if(send_notification(1) == 0) {
                // TODO: Set default policy to encap

                state = GATEWAY_NOTIFICATION_SUCCEEDED;
            }
        }

        sleep(RETRY_DELAY);
    }

    return 0;
}

