#include <stdlib.h>
#include <time.h>
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

int main(int argc, char* argv[])
{
    int result;

    DEBUG_MSG("Starting wigateway version %d.%d",
              WIROVER_VERSION_MAJOR, WIROVER_VERSION_MINOR);

    srand(time(0));

    const char* wiroot_ip = get_wiroot_ip();
    const unsigned short wiroot_port = get_wiroot_port();
    unsigned short base_port = get_base_port();
    if(!(wiroot_ip && wiroot_port && base_port)) {
        DEBUG_MSG("You must fix the config file.");
        exit(1);
    } 

    uint32_t my_priv_ip = 0;
    inet_pton(AF_INET, DEFAULT_VIRT_ADDRESS, &my_priv_ip);

    uint32_t my_netmask = 0;
    inet_pton(AF_INET, DEFAULT_NETMASK, &my_netmask);

    const struct lease_info* lease = obtain_lease(wiroot_ip, wiroot_port, base_port);
    if(lease) {
        char my_ip[INET6_ADDRSTRLEN];
        ipaddr_to_string(&lease->priv_ip, my_ip, sizeof(my_ip));
        DEBUG_MSG("Obtained lease of %s and unique id %u", my_ip, lease->unique_id);
        DEBUG_MSG("There are %d controllers available.", lease->controllers);

        if(lease->controllers > 0) {
            char cont_ip[INET6_ADDRSTRLEN];
            ipaddr_to_string(&lease->cinfo[0].pub_ip, cont_ip, sizeof(cont_ip));
            DEBUG_MSG("First controller is at: %s", cont_ip);

            uint32_t priv_ip;
            uint32_t pub_ip;
            uint32_t netmask = 0xffffffff;

            ipaddr_to_ipv4(&lease->cinfo[0].priv_ip, &priv_ip);
            ipaddr_to_ipv4(&lease->cinfo[0].pub_ip, &pub_ip);

            virt_add_remote_node((struct in_addr *)&priv_ip, (struct in_addr *)&netmask);
            virt_add_remote_link((struct in_addr *)&priv_ip, 
                (struct in_addr *)&pub_ip, lease->cinfo[0].base_port);

            // Add a default vroute that directs all traffic to the controller
            virt_add_vroute(0, 0, priv_ip);
        }
        
        ipaddr_to_ipv4(&lease->priv_ip, &my_priv_ip);
        my_netmask = htonl(~((1 << lease->priv_subnet_size) - 1));
    } else {
        DEBUG_MSG("Failed to obtain a lease from wiroot server.");
        DEBUG_MSG("We will use the IP address %s and NAT mode.", DEFAULT_VIRT_ADDRESS);
    }

    result = setup_virtual_interface(my_priv_ip, my_netmask);
    if(result == -1) {
        DEBUG_MSG("Failed to bring up virtual interface");
    }
    
    if(create_netlink_thread() == -1) {
        DEBUG_MSG("Failed to create netlink thread");
    }
    
    result = init_interface_list();
    if(result == -1) {
        DEBUG_MSG("Failed to initialize interface list");
    }

    if(lease) {
        if(start_ping_thread() == FAILURE) {
            DEBUG_MSG("Cannot continue due to ping thread failure");
            exit(1);
        }
    }

    wait_for_netlink_thread();

    return 0;
}

