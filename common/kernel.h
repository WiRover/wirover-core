#ifndef _KERNEL_H_
#define _KERNEL_H_

#define SIOCVIRTENSLAVE   (SIOCDEVPRIVATE + 0)
#define SIOCVIRTRELEASE   (SIOCDEVPRIVATE + 1)
#define SIOCVIRTSETHWADDR (SIOCDEVPRIVATE + 2)
#define SIOCVIRTSETGWADDR (SIOCDEVPRIVATE + 3)
#define SIOCVIRTADDVROUTE (SIOCDEVPRIVATE + 4)
#define SIOCVIRTDELVROUTE (SIOCDEVPRIVATE + 5)
#define SIOCVIRTSETPOLICY (SIOCDEVPRIVATE + 6)
#define SIOCVIRTSETLPRIO  (SIOCDEVPRIVATE + 7)
#define SIOCVIRTSETRPRIO  (SIOCDEVPRIVATE + 8)
#define SIOCVIRTPERFHINT  (SIOCDEVPRIVATE + 9)

#define VIRT_PROC_REMOTE_ADD     0
#define VIRT_PROC_REMOTE_DELETE  1

struct virt_proc_remote_node {
    unsigned op;
    struct in_addr priv_ip;
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


enum {
    LOCAL_BANDWIDTH_HINT = 0,
    REMOTE_BANDWIDTH_HINT,
};

struct virt_perf_hint {
    int type;

    union {
        int local_dev;
        __be32 remote_addr;
    } vph_dev;
#define vph_local_dev vph_dev.local_dev
#define vph_remote_addr vph_dev.remote_addr

    long bandwidth;
};


int setup_virtual_interface(__be32 ip, __be32 netmask, unsigned mtu);

int kernel_enslave_device(const char* device);
int kernel_release_device(const char* device);

int virt_add_remote_node(const struct in_addr *priv_ip);
int virt_add_remote_link(const struct in_addr *priv_ip,
        const struct in_addr *pub_ip, unsigned short data_port);

int virt_remove_remote_node(const struct in_addr *priv_ip);
int virt_remove_remote_link(const struct in_addr *priv_ip,
        const struct in_addr *pub_ip);

int virt_set_gateway_ip(const char *device, const struct in_addr *gw_ip);

int virt_add_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip);
int virt_delete_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip);

int virt_local_bandwidth_hint(int local_dev, long bandwidth);
int virt_remote_bandwidth_hint(__be32 remote_addr, long bandwidth);

int add_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);
int delete_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);

#endif //_KERNEL_H_

