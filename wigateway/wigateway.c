#include <stdlib.h>
#include <arpa/inet.h>

#include "config.h"
#include "contchan.h"
#include "debug.h"
#include "netlink.h"
#include "rootchan.h"
#include "virtInterface.h"

const char* WIROOT_ADDRESS = "128.105.22.229";
const unsigned short WIROOT_PORT = 8088;

int main(int argc, char* argv[])
{
    int result;

    DEBUG_MSG("Starting wigateway version %d.%d",
              WIROVER_VERSION_MAJOR, WIROVER_VERSION_MINOR);

    const struct lease_info* lease = obtain_lease(WIROOT_ADDRESS, WIROOT_PORT);
    if(lease == 0) {
        DEBUG_MSG("Fatal error: failed to obtain a lease from wiroot server");
//        exit(1);
    }

    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &lease->priv_ip, p_ip, sizeof(p_ip));
    DEBUG_MSG("Obtained lease of %s and unique id %u", p_ip, lease->unique_id);

    DEBUG_MSG("There are %d controllers available.", lease->controllers);

    result = setup_virtual_interface(p_ip);
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

    result = send_notification(lease);
    if(result == -1) {
        DEBUG_MSG("Failed to send notification to controller.");
    }

    wait_for_netlink_thread();

    return 0;
}

