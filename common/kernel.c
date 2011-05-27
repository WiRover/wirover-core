#include <netdb.h>
#include <stropts.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "debug.h"
#include "kernel.h"

const char* VIRT_DEVICE = "virt0";

/*
 * SETUP VIRTUAL INTERFACE
 */
int setup_virtual_interface(const char *ip)
{
    int sockfd;
    struct addrinfo hints;
    struct addrinfo *ainfo = 0;
    int result;

    /* TODO: struct ifreq only has space for a sockaddr, so only IPv4
     * addresses can be added with the current code. */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_NUMERICHOST;

    result = getaddrinfo(ip, 0, &hints, &ainfo);
    if(result != 0 || !ainfo) {
        DEBUG_MSG("getaddrinfo() failed - %s", gai_strerror(result));
        return -1;
    }

    sockfd = socket(ainfo->ai_family, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        freeaddrinfo(ainfo);
        return -1;
    }
    
    struct ifreq master_ifr;
    memset(&master_ifr, 0, sizeof(struct ifreq));
    memcpy(&master_ifr.ifr_addr, ainfo->ai_addr, ainfo->ai_addrlen);
    strncpy(master_ifr.ifr_name, VIRT_DEVICE, IFNAMSIZ);

    freeaddrinfo(ainfo);

    result = ioctl(sockfd, SIOCSIFADDR, &master_ifr);
    if(result < 0) {
        ERROR_MSG("SIOCSIFADDR ioctl failed");
        close(sockfd);
        return -1;
    }

    master_ifr.ifr_flags |= IFF_UP;

    result = ioctl(sockfd, SIOCSIFFLAGS, &master_ifr);
    if(result < 0) {
        ERROR_MSG("SIOCSIFFLAGS ioctl failed");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

int kernel_enslave_device(const char* device)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));
    strncpy(ifr.ifr_slave, device, sizeof(ifr.ifr_slave));
    
    if(ioctl(sockfd, SIOCVIRTENSLAVE, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTENSLAVE ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;
}

int kernel_release_device(const char* device)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));
    strncpy(ifr.ifr_slave, device, sizeof(ifr.ifr_slave));
    
    if(ioctl(sockfd, SIOCVIRTRELEASE, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTRELEASE ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;
}


int virt_add_remote_node(const struct in_addr *priv_ip,   
                const struct in_addr *netmask)
{
    struct virt_proc_remote_node node;
    memset(&node, 0, sizeof(node));

    node.op = VIRT_PROC_REMOTE_ADD;
    memcpy(&node.priv_ip, priv_ip, sizeof(node.priv_ip));
    memcpy(&node.netmask, netmask, sizeof(node.netmask));

    int fd = open("/proc/virtmod/remote/nodes", O_WRONLY);
    if(fd < 0) {
        ERROR_MSG("open /proc/virtmod/remote/nodes failed");
        return -1;
    }

    int written = write(fd, &node, sizeof(node));
    if(written < sizeof(node)) {
        ERROR_MSG("write failed");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int virt_add_remote_link(const struct in_addr *priv_ip,
                const struct in_addr *pub_ip, unsigned short data_port)
{
    struct virt_proc_remote_link link;
    memset(&link, 0, sizeof(link));

    link.op = VIRT_PROC_REMOTE_ADD;
    memcpy(&link.priv_ip, priv_ip, sizeof(link.priv_ip));
    memcpy(&link.pub_ip, pub_ip, sizeof(link.pub_ip));
    link.data_port = data_port;

    int fd = open("/proc/virtmod/remote/links", O_WRONLY);
    if(fd < 0) {
        ERROR_MSG("open /proc/virtmod/remote/links failed");
        return -1;
    }

    int written = write(fd, &link, sizeof(link));
    if(written < sizeof(link)) {
        ERROR_MSG("write failed");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}


int virt_remove_remote_node(const struct in_addr *priv_ip)
{
    struct virt_proc_remote_node node;
    memset(&node, 0, sizeof(node));

    node.op = VIRT_PROC_REMOTE_DELETE;
    memcpy(&node.priv_ip, priv_ip, sizeof(node.priv_ip));

    int fd = open("/proc/virtmod/remote/nodes", O_WRONLY);
    if(fd < 0) {
        ERROR_MSG("open /proc/virtmod/remote/nodes failed");
        return -1;
    }

    int written = write(fd, &node, sizeof(node));
    if(written < sizeof(node)) {
        ERROR_MSG("write failed");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int virt_remove_remote_link(const struct in_addr *priv_ip,
                const struct in_addr *pub_ip)
{
    struct virt_proc_remote_link link;
    memset(&link, 0, sizeof(link));

    link.op = VIRT_PROC_REMOTE_DELETE;
    memcpy(&link.priv_ip, priv_ip, sizeof(link.priv_ip));
    memcpy(&link.pub_ip, pub_ip, sizeof(link.pub_ip));

    int fd = open("/proc/virtmod/remote/links", O_WRONLY);
    if(fd < 0) {
        ERROR_MSG("open /proc/virtmod/remote/links failed");
        return -1;
    }

    int written = write(fd, &link, sizeof(link));
    if(written < sizeof(link)) {
        ERROR_MSG("write failed");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int virt_set_gateway_ip(const char *device, const struct in_addr *gw_ip)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }
    
    struct gwaddr_req gwa_req;
    memset(&gwa_req, 0, sizeof(gwa_req));
    strncpy(gwa_req.ifname, device, sizeof(gwa_req.ifname));
    gwa_req.family = AF_INET;
    gwa_req.gwaddr_ip4 = gw_ip->s_addr;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));
    ifr.ifr_data = &gwa_req;

    if(ioctl(sockfd, SIOCVIRTSETGWADDR, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTSETGWADDR ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;
}

int virt_set_proxy(const struct in_addr *priv_ip, unsigned short data_port)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    memcpy(&addr->sin_addr, priv_ip, sizeof(struct in_addr));
    addr->sin_port = data_port;
    
    if(ioctl(sockfd, SIOCVIRTSETPROXY, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTSETPROXY ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;
}

