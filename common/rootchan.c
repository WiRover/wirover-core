#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "configuration.h"
#include "debug.h"
#include "rootchan.h"
#include "sockets.h"

static struct lease_info* latest_lease = 0;

/*
 * OBTAIN LEASE
 */
struct lease_info* obtain_lease(const char* wiroot_ip, unsigned short wiroot_port, unsigned short base_port)
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
    request.base_port = htons(base_port);

    const char* internal_if = get_internal_interface();
    if(!internal_if) {
        close(sockfd);
        return 0;
    }

    result = get_device_mac(internal_if, request.hw_addr, sizeof(request.hw_addr));
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
    } else if(bytes < MIN_RESPONSE_LEN) {
        DEBUG_MSG("lease response was too small to be valid");
        close(sockfd);
        return 0;
    }

    close(sockfd);

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

    if(response.controllers == 0) {
        lease->cinfo = 0;
        latest_lease = lease;
        return lease;
    }
   
    const int cinfo_size = lease->controllers * sizeof(struct controller_info);
    lease->cinfo = (struct controller_info*)malloc(cinfo_size);
    ASSERT_OR_ELSE(lease->cinfo) {
        DEBUG_MSG("out of memory");
        free(lease);
        return 0;
    }
    
    memcpy(lease->cinfo, response.cinfo, cinfo_size);

    latest_lease = lease;
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

void get_private_ip(ipaddr_t* dest)
{
    if(latest_lease) {
        copy_ipaddr(&latest_lease->priv_ip, dest);
    } else {
        memset(dest, 0, sizeof(*dest));
    }
}

uint16_t get_unique_id()
{
    if(latest_lease) {
        return latest_lease->unique_id;
    } else {
        return 0;
    }
}

const struct lease_info* get_lease_info()
{
    return latest_lease;
}

/*
 * GET CONTROLLER BASE PORT
 *
 * Returns controller's base port in host byte order.
 */
unsigned short get_controller_base_port()
{
    if(!latest_lease || latest_lease->controllers == 0) {
        DEBUG_MSG("There are no controllers.");
        return FAILURE;
    }

    return ntohs(latest_lease->cinfo[0].base_port);
}

/*
 * GET CONTROLLER IP
 *
 * It is recommended that your buffer be at least INET6_ADDRSTRLEN bytes in
 * size.
 */
int get_controller_ip(char* dest, int dest_len)
{
    if(!latest_lease || latest_lease->controllers == 0) {
        DEBUG_MSG("There are no controllers.");
        return FAILURE;
    }

    inet_ntop(AF_INET, &latest_lease->cinfo[0].pub_ip, dest, dest_len);
    return 0;
}


