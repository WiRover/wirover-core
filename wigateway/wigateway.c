#include <stdlib.h>
#include <arpa/inet.h>

#include "contchan.h"
#include "debug.h"
#include "virtInterface.h"

const char* WIROOT_ADDRESS = "128.105.22.229";
const unsigned short WIROOT_PORT = 8088;

int main(int argc, char* argv[])
{
    uint32_t priv_ip;
    int result;

    DEBUG_MSG("Starting wigateway...");

    priv_ip = obtain_lease(WIROOT_ADDRESS, WIROOT_PORT);
    if(priv_ip == -1) {
        DEBUG_MSG("Fatal error: failed to obtain a lease from wiroot server");
        exit(1);
    }

    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &priv_ip, p_ip, sizeof(p_ip));

    DEBUG_MSG("Obtained lease of %s", p_ip);

    result = setup_virtual_interface(p_ip);
    if(result == -1) {
        DEBUG_MSG("Fatal error: failed to bring up virtual interface");
        exit(1);
    }

    return 0;
}

