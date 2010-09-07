#include <stdlib.h>
#include <arpa/inet.h>

#include "contchan.h"
#include "debug.h"
#include "netlink.h"
#include "virtInterface.h"
#include "common/rootchan.h"

const char* WIROOT_ADDRESS = "128.105.22.229";
const unsigned short WIROOT_PORT = 8088;

int main(int argc, char* argv[])
{
    int result;

    DEBUG_MSG("Starting wigateway...");

    const struct lease_info* lease = obtain_lease(WIROOT_ADDRESS, WIROOT_PORT);
    if(lease == 0) {
        DEBUG_MSG("Fatal error: failed to obtain a lease from wiroot server");
//        exit(1);
    }

    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &lease->priv_ip, p_ip, sizeof(p_ip));
    DEBUG_MSG("Obtained lease of %s and unique id %u", p_ip, lease->unique_id);

    result = setup_virtual_interface(p_ip);
    if(result == -1) {
        DEBUG_MSG("Fatal error: failed to bring up virtual interface");
//        exit(1);
    }

    result = init_interface_list();
    if(result == -1) {
        DEBUG_MSG("Failed to initialize interface list");
    }

    return 0;
}

