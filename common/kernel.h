#ifndef _KERNEL_H_
#define _KERNEL_H_

#define SIOCVIRTENSLAVE   (SIOCDEVPRIVATE + 0)
#define SIOCVIRTRELEASE   (SIOCDEVPRIVATE + 1)
#define SIOCVIRTSETHWADDR (SIOCDEVPRIVATE + 2)
#define SIOCVIRTSETGWADDR (SIOCDEVPRIVATE + 4)
#define SIOCVIRTADDVROUTE (SIOCDEVPRIVATE + 5)
#define SIOCVIRTDELVROUTE (SIOCDEVPRIVATE + 6)

#define VIRT_PROC_REMOTE_ADD     0
#define VIRT_PROC_REMOTE_DELETE  1

// TODO: Check MTU of every enslaved device.  We need to use the minimum MTU.
// IP (no options) + UDP header is 28 bytes.
#define VIRT_MTU (1500 - 28 - sizeof(struct tunhdr))

struct virt_proc_remote_node {
    unsigned op;
    struct in_addr priv_ip;
    struct in_addr netmask;
};

struct virt_proc_remote_link {
    unsigned op;
    struct in_addr priv_ip;
    struct in_addr pub_ip;
    uint16_t data_port;
};

struct gwaddr_req {
    char     ifname[IFNAMSIZ];

    // family should be either AF_INET or AF_INET6
    uint16_t family;

    union {
        __be32          ip4_u;
        struct in6_addr ip6_u;
    } nl_u;
#define gwaddr_ip4 nl_u.ip4_u
#define gwaddr_ip6 nl_u.ip6_u
};

struct vroute_req {
    __be32 dest;
    __be32 netmask;
    __be32 node_ip;
};

int setup_virtual_interface(const char *ip);

int kernel_enslave_device(const char* device);
int kernel_release_device(const char* device);

int virt_add_remote_node(const struct in_addr *priv_ip, 
        const struct in_addr *netmask);
int virt_add_remote_link(const struct in_addr *priv_ip,
        const struct in_addr *pub_ip, unsigned short data_port);

int virt_remove_remote_node(const struct in_addr *priv_ip);
int virt_remove_remote_link(const struct in_addr *priv_ip,
        const struct in_addr *pub_ip);

int virt_set_gateway_ip(const char *device, const struct in_addr *gw_ip);

int virt_add_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip);
int virt_delete_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip);

#endif //_KERNEL_H_

