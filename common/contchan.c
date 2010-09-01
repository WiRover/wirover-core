#include <math.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "contchan.h"
#include "debug.h"
#include "sockets.h"

static uint32_t private_ip = 0;
static uint16_t unique_id = 0;

/*
 * OBTAIN LEASE
 *
 * Returns a valid IPv4 address or 0 on error.
 */
uint32_t obtain_lease(const char* wiroot_ip, unsigned short wiroot_port)
{
    int sockfd;
    int bytes;
    int result;
    
    sockfd = tcp_active_open(wiroot_ip, wiroot_port);
    if(sockfd == -1) {
        DEBUG_MSG("failed to connect to wiroot server");
        return 0;
    }

    struct cchan_request request;
#ifdef CONTROLLER
    request.type = CCHAN_CONTROLLER_CONFIG;
#else
    request.type = CCHAN_GATEWAY_CONFIG;
#endif
    request.latitude = NAN;
    request.longitude = NAN;

    // TODO: get internal interface name from somewhere else
    result = get_device_mac("eth0", request.hw_addr, sizeof(request.hw_addr));
    if(result == -1) {
        DEBUG_MSG("get_device_mac() failed");
        return 0;
    }

    bytes = send(sockfd, &request, sizeof(struct cchan_request), 0);
    if(bytes <= 0) {
        ERROR_MSG("error sending lease request");
        return 0;
    }

    char pkt_buff[1024];

    bytes = recv(sockfd, pkt_buff, sizeof(pkt_buff), 0);
    if(bytes <= 0) {
        ERROR_MSG("error receiving lease response");
        return 0;
    } else if(bytes < sizeof(struct cchan_response)) {
        DEBUG_MSG("lease response was too small to be valid");
        return 0;
    }

    close(sockfd);

    struct cchan_response* response = (struct cchan_response*)pkt_buff;
    private_ip = response->priv_ip;
    unique_id = response->unique_id;

    return response->priv_ip;
}

/*
 * GET DEVICE MAC
 *
 * Return -1 on failure or the size in bytes of the MAC address (should be 6)
 * copied to dest.
 */
int get_device_mac(const char* __restrict__ device, uint8_t* __restrict__ dest, int destlen)
{
    struct ifreq ifr;
    int sockfd;
    int result;

    strncpy(ifr.ifr_name, device, IFNAMSIZ);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        ERROR_MSG("error creating socket");
        return -1;
    }

    result = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(result < 0) {
        ERROR_MSG("SIOCGIFHWADDR ioctl failed");
        return -1;
    }

    const int copy_bytes = (destlen >= sizeof(ifr.ifr_hwaddr.sa_data)) ? 
                           sizeof(ifr.ifr_hwaddr.sa_data) : destlen;
    memcpy(dest, ifr.ifr_hwaddr.sa_data, copy_bytes);

    return copy_bytes;
}

