#include <netdb.h>
//#include <stropts.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/route.h>
#include <net/if.h>

#include "debug.h"
#include "kernel.h"
#include "tunnel.h"
#include "config.h"

const char* VIRT_DEVICE = "virt0";

/*
 * Bring up the virtual interface and set its IP address, netmask, and MTU.
 */
int setup_virtual_interface(__be32 ip, __be32 netmask, unsigned mtu)
{
    int sockfd;
    int result;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return -1;
    }
    
    struct ifreq master_ifr;
    memset(&master_ifr, 0, sizeof(struct ifreq));

    struct sockaddr_in *addr = (struct sockaddr_in *)&master_ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;
    strncpy(master_ifr.ifr_name, VIRT_DEVICE, IFNAMSIZ);

    result = ioctl(sockfd, SIOCSIFADDR, &master_ifr);
    if(result < 0) {
        ERROR_MSG("SIOCSIFADDR ioctl failed");
        close(sockfd);
        return -1;
    }

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = netmask;

    result = ioctl(sockfd, SIOCSIFNETMASK, &master_ifr);
    if(result < 0) {
        ERROR_MSG("SIOCSIFNETMASK ioctl failed");
        close(sockfd);
        return -1;
    }

    result = ioctl(sockfd, SIOCGIFFLAGS, &master_ifr);
    if(result < 0) {
        ERROR_MSG("SIOCGIFFLAGS ioctl failed");
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

    master_ifr.ifr_mtu = mtu;

    result = ioctl(sockfd, SIOCSIFMTU, &master_ifr);
    if(result < 0) {
        ERROR_MSG("SIOCSIFMTU ioctl failed");
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
    
#ifdef USE_BOND_ENSLAVE
    if(ioctl(sockfd, SIOCBONDENSLAVE, &ifr) < 0) {
        ERROR_MSG("SIOCBONDENSLAVE ioctl failed");
        close(sockfd);
        return FAILURE;
    }
#else
    if(ioctl(sockfd, SIOCVIRTENSLAVE, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTENSLAVE ioctl failed");
        close(sockfd);
        return FAILURE;
    }
#endif

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

#ifdef USE_BOND_ENSLAVE
    if(ioctl(sockfd, SIOCBONDRELEASE, &ifr) < 0) {
        ERROR_MSG("SIOCBONDRELEASE ioctl failed");
        close(sockfd);
        return FAILURE;
    }
#else
    if(ioctl(sockfd, SIOCVIRTRELEASE, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTRELEASE ioctl failed");
        close(sockfd);
        return FAILURE;
    }
#endif

    close(sockfd);
    return 0;
}


int virt_add_remote_node(const struct in_addr *priv_ip)
{
    struct virt_proc_remote_node node;
    memset(&node, 0, sizeof(node));

    node.op = VIRT_PROC_REMOTE_ADD;
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

int virt_add_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    struct vroute_req vroute_req;
    memset(&vroute_req, 0, sizeof(vroute_req));
    vroute_req.dest = dest;
    vroute_req.netmask = netmask;
    vroute_req.node_ip = node_ip;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));
    ifr.ifr_data = &vroute_req;

    if(ioctl(sockfd, SIOCVIRTADDVROUTE, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTADDVROUTE ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;
}

int virt_delete_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    struct vroute_req vroute_req;
    memset(&vroute_req, 0, sizeof(vroute_req));
    vroute_req.dest = dest;
    vroute_req.netmask = netmask;
    vroute_req.node_ip = node_ip;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));
    ifr.ifr_data = &vroute_req;

    if(ioctl(sockfd, SIOCVIRTDELVROUTE, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTDELVROUTE ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;
}

/*
 * Set the priority for a local interface.
 */
int virt_local_prio(int local_dev, int prio)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    struct virt_setlprio_req req;
    memset(&req, 0, sizeof(req));
    if_indextoname(local_dev, req.ifname);
    req.prio = prio;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));
    ifr.ifr_data = &req;

    if(ioctl(sockfd, SIOCVIRTSETLPRIO, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTSETLPRIO ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;
}

/*
 * Set the priority for a remote interface.
 */
int virt_remote_prio(const struct in_addr *remote_node, const struct in_addr *remote_addr, int prio)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    struct virt_setrprio_req req;
    memset(&req, 0, sizeof(req));
    req.node_ip = remote_node->s_addr;
    req.link_ip = remote_addr->s_addr;
    req.prio = prio;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, VIRT_DEVICE, sizeof(ifr.ifr_name));
    ifr.ifr_data = &req;

    if(ioctl(sockfd, SIOCVIRTSETRPRIO, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTSETRPRIO ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);
    return 0;

}

static int send_perf_hint(const char *master, struct virt_perf_hint *hint)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, master, sizeof(ifr.ifr_name));
    ifr.ifr_data = hint;

    if(ioctl(sockfd, SIOCVIRTPERFHINT, &ifr) < 0) {
        ERROR_MSG("SIOCVIRTPERFHINT ioctl failed");
        close(sockfd);
        return FAILURE;
    }

    close(sockfd);

    return 0;
}

int virt_local_bandwidth_hint(int local_dev, long bandwidth)
{
    struct virt_perf_hint hint;
    hint.type = LOCAL_BANDWIDTH_HINT;
    hint.vph_local_dev = local_dev;
    hint.bandwidth = bandwidth;

    return send_perf_hint(VIRT_DEVICE, &hint);
}

int virt_remote_bandwidth_hint(__be32 remote_addr, long bandwidth)
{
    struct virt_perf_hint hint;
    hint.type = REMOTE_BANDWIDTH_HINT;
    hint.vph_remote_addr = remote_addr;
    hint.bandwidth = bandwidth;

    return send_perf_hint(VIRT_DEVICE, &hint);
}

int add_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device)
{
    struct rtentry rt;
    char dev_buf[IFNAMSIZ];

    memset(&rt, 0, sizeof(rt));
    memset(dev_buf, 0, sizeof(dev_buf));

    rt.rt_flags = RTF_UP;

    rt.rt_dst.sa_family = AF_INET;
    struct in_addr *addr_dst = &((struct sockaddr_in *)&rt.rt_dst)->sin_addr;
    addr_dst->s_addr = dest;

    rt.rt_genmask.sa_family = AF_INET;
    struct in_addr *netmask_dst = &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr;
    netmask_dst->s_addr = netmask;

    if(gateway) {
        rt.rt_flags |= RTF_GATEWAY;

        rt.rt_gateway.sa_family = AF_INET;
        struct in_addr *gw_dst = &((struct sockaddr_in *)&rt.rt_gateway)->sin_addr;
        gw_dst->s_addr = gateway;
    }

    if(device) {
        strncpy(dev_buf, device, sizeof(dev_buf));
        rt.rt_dev = dev_buf;
    }

    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd < 0) {
        ERROR_MSG("creating socket failed");
        return -errno;
    }

    int rtn = ioctl(skfd, SIOCADDRT, &rt);
    if(rtn == -1) {
        if(errno != EEXIST)
            ERROR_MSG("ioctl SIOCADDRT failed");

        close(skfd);
        return -errno;
    }

    close(skfd);
    return 0;
}

int delete_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device)
{
    struct rtentry rt;
    char dev_buf[IFNAMSIZ];

    memset(&rt, 0, sizeof(rt));
    memset(dev_buf, 0, sizeof(dev_buf));

    rt.rt_dst.sa_family = AF_INET;
    struct in_addr *addr_dst = &((struct sockaddr_in *)&rt.rt_dst)->sin_addr;
    addr_dst->s_addr = dest;

    rt.rt_genmask.sa_family = AF_INET;
    struct in_addr *netmask_dst = &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr;
    netmask_dst->s_addr = netmask;

    if(gateway) {
        rt.rt_flags |= RTF_GATEWAY;

        rt.rt_gateway.sa_family = AF_INET;
        struct in_addr *gw_dst = &((struct sockaddr_in *)&rt.rt_gateway)->sin_addr;
        gw_dst->s_addr = gateway;
    }

    if(device) {
        strncpy(dev_buf, device, sizeof(dev_buf));
        rt.rt_dev = dev_buf;
    }

    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd < 0) {
        ERROR_MSG("creating socket failed");
        return -errno;
    }

    int rtn = ioctl(skfd, SIOCDELRT, &rt);
    if(rtn == -1) {
        ERROR_MSG("ioctl SIOCDELRT failed");
        close(skfd);
        return -errno;
    }

    close(skfd);
    return 0;
}

