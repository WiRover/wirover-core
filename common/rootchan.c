#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "debug.h"
#include "rootchan.h"
#include "sockets.h"

/*
 * OBTAIN LEASE
 */
struct lease_info* obtain_lease(const char* wiroot_ip, unsigned short wiroot_port)
{
    int sockfd;
    int bytes;
    int result;
    
    sockfd = tcp_active_open(wiroot_ip, wiroot_port);
    if(sockfd == -1) {
        DEBUG_MSG("failed to connect to wiroot server");
        return 0;
    }

    struct rchan_request request;
#ifdef CONTROLLER
    request.type = RCHAN_CONTROLLER_CONFIG;
#else
    request.type = RCHAN_GATEWAY_CONFIG;
#endif
    request.latitude = NAN;
    request.longitude = NAN;

    // TODO: get internal interface name from somewhere else
    result = get_device_mac("eth0", request.hw_addr, sizeof(request.hw_addr));
    if(result == -1) {
        DEBUG_MSG("get_device_mac() failed");
        close(sockfd);
        return 0;
    }

    bytes = send(sockfd, &request, sizeof(struct rchan_request), 0);
    if(bytes <= 0) {
        ERROR_MSG("error sending lease request");
        close(sockfd);
        return 0;
    }

    struct rchan_response response;
    bytes = recv(sockfd, &response, sizeof(response), 0);
    if(bytes <= 0) {
        ERROR_MSG("error receiving lease response");
        close(sockfd);
        return 0;
    } else if(bytes < sizeof(struct rchan_response)) {
        DEBUG_MSG("lease response was too small to be valid");
        close(sockfd);
        return 0;
    }

    struct lease_info* lease;
    lease = (struct lease_info*)malloc(sizeof(struct lease_info));
    ASSERT_OR_ELSE(lease) {
        DEBUG_MSG("out of memory");
        close(sockfd);
        return 0;
    }

    lease->priv_ip = response.priv_ip;
    lease->unique_id = ntohs(response.unique_id);
    lease->controllers = response.controllers;
    
    const int cinfo_size = lease->controllers * sizeof(struct rchan_controller_info);
    lease->cinfo = (struct rchan_controller_info*)malloc(cinfo_size);
    ASSERT_OR_ELSE(lease->cinfo) {
        DEBUG_MSG("out of memory");
        free(lease);
        close(sockfd);
        return 0;
    }

    bytes = recv(sockfd, lease->cinfo, cinfo_size, 0);
    if(bytes <= 0) {
        ERROR_MSG("error receiving lease response");
        free(lease->cinfo);
        free(lease);
        close(sockfd);
        return 0;
    } else if(bytes < cinfo_size) {
        DEBUG_MSG("lease response was too small to be valid");
        free(lease->cinfo);
        free(lease);
        close(sockfd);
        return 0;
    }

    close(sockfd);
    return lease;
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



