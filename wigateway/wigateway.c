#include <stdlib.h>
#include <arpa/inet.h>

#include "config.h"
#include "configuration.h"
#include "contchan.h"
#include "debug.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "kernel.h"
#include "remote_nodes.h"

// The virtual interface will use this IP address if we are unable to obtain a
// private IP from the root server.
const char* DEFAULT_VIRT_ADDRESS = "172.31.25.1";

int main(int argc, char* argv[])
{
    int result;

    DEBUG_MSG("Starting wigateway version %d.%d",
              WIROVER_VERSION_MAJOR, WIROVER_VERSION_MINOR);

    const char* wiroot_ip = get_wiroot_ip();
    const unsigned short wiroot_port = get_wiroot_port();
    unsigned short base_port = get_base_port();
    if(!(wiroot_ip && wiroot_port && base_port)) {
        DEBUG_MSG("You must fix the config file.");
        exit(1);
    } 

    char my_ip[INET6_ADDRSTRLEN];
    strncpy(my_ip, DEFAULT_VIRT_ADDRESS, sizeof(my_ip));

    const struct lease_info* lease = obtain_lease(wiroot_ip, wiroot_port, base_port);
    if(lease == 0) {
        DEBUG_MSG("Failed to obtain a lease from wiroot server.");
        DEBUG_MSG("We will use the IP address %s and NAT mode.", DEFAULT_VIRT_ADDRESS);
    } else {
        ipaddr_to_string(&lease->priv_ip, my_ip, sizeof(my_ip));
        DEBUG_MSG("Obtained lease of %s and unique id %u", my_ip, lease->unique_id);
        DEBUG_MSG("There are %d controllers available.", lease->controllers);

        if(lease->controllers > 0) {
            char cont_ip[INET6_ADDRSTRLEN];
            ipaddr_to_string(&lease->cinfo[0].pub_ip, cont_ip, sizeof(cont_ip));
            DEBUG_MSG("First controller is at: %s", cont_ip);

            //struct sockaddr_in caddr;
            //get_controller_addr((struct sockaddr*)&caddr, sizeof(caddr));

            struct virt_proc_remote_node remote_node;
            remote_node.op          = PROC_REMOTE_ADD;
            remote_node.base_port   = lease->cinfo[0].base_port;
            copy_ipaddr(&lease->cinfo[0].priv_ip, &remote_node.priv_ip);
            change_remote_node_table(&remote_node);

            struct virt_proc_remote_link remote_link;
            remote_link.op          = PROC_REMOTE_ADD;
            copy_ipaddr(&lease->cinfo[0].priv_ip, &remote_link.priv_ip);
            copy_ipaddr(&lease->cinfo[0].pub_ip, &remote_link.pub_ip);
            change_remote_link_table(&remote_link);

            //if(kernel_set_controller(&caddr) == FAILURE) {
            //    DEBUG_MSG("Failed to set controller in kernel module");
            //}
        }
    }

    result = setup_virtual_interface(my_ip);
    if(result == -1) {
        DEBUG_MSG("Fatal error: failed to bring up virtual interface");
//        exit(1);
    }
    
    if(create_netlink_thread() == -1) {
        DEBUG_MSG("Failed to create netlink thread");
    }
    
    result = init_interface_list();
    if(result == -1) {
        DEBUG_MSG("Failed to initialize interface list");
    }

    if(start_ping_thread() == FAILURE) {
        DEBUG_MSG("Cannot continue due to ping thread failure");
        exit(1);
    }

    if(send_notification() == FAILURE) {
        DEBUG_MSG("Failed to send notification to controller.");
    }

    wait_for_netlink_thread();

    return 0;
}

