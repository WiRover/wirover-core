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
#define SIOCVIRTCONF      (SIOCDEVPRIVATE + 15)

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

struct virt_setlprio_req {
    char ifname[IFNAMSIZ];
    int prio;
};

struct virt_setrprio_req {
    __be32 node_ip;
    __be32 link_ip;
    int prio;
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

#define VIRT_CONF_ADD_REMOTE_NODE   0x0000
#define VIRT_CONF_DEL_REMOTE_NODE   0x0001
#define VIRT_CONF_ADD_REMOTE_LINK   0x0002
#define VIRT_CONF_DEL_REMOTE_LINK   0x0003
#define VIRT_CONF_SET_XOR_RATE2     0x0005
#define VIRT_CONF_GET_DEV_FLAGS     0x0006
#define VIRT_CONF_SET_DEV_FLAGS     0x0007

struct virt_conf_remote_node {
    struct in_addr priv_ip;
};

struct virt_conf_remote_link {
    // priv_ip identifies the node to which this link belongs, so the node must
    // be added before a link is added.
    struct in_addr priv_ip;
    struct in_addr pub_ip;

    __be16 data_port;
};

struct virt_conf_xor_rate2 {
    /* The combination of addresses and ports identifies the path. */
    struct in_addr local_addr;
    struct in_addr remote_addr;
    __be16 local_port;
    __be16 remote_port;

    /* XOR coding rates interpreted as the number of packets used to produce a
     * coded packet.  Setting the rate to zero disables coding; setting it to
     * one results in duplication. 
     * 
     * same_path: coded packets are sent on the same path as the data packets.
     * same_prio: coded packets are sent on other paths with the same priority.
     * lower_prio: coded packets are sent on paths with lower priority.
     */
    unsigned char same_path;
    unsigned char same_prio;
    unsigned char lower_prio;
};

#define DEVICE_NO_TX 0x00000001

struct virt_conf_dev_flags {
    char ifname[IFNAMSIZ];
    uint32_t flags;
};

struct virt_conf_message {
    unsigned op;

    union {
        struct virt_conf_remote_node remote_node;
        struct virt_conf_remote_link remote_link;
        struct virt_conf_xor_rate2   xor_rate2;
        struct virt_conf_dev_flags   dev_flags;
    } msg;
};



int setup_virtual_interface(__be32 ip, __be32 netmask, unsigned mtu);

int kernel_enslave_device(const char* device);
int kernel_release_device(const char* device);

int virt_add_remote_node(const struct in_addr *priv_ip);
int virt_add_remote_link(const struct in_addr *priv_ip,
        const struct in_addr *pub_ip, unsigned short data_port);

int virt_remove_remote_node(const struct in_addr *priv_ip);
int virt_remove_remote_link(const struct in_addr *priv_ip,
        const struct in_addr *pub_ip, unsigned short data_port);

int virt_set_gateway_ip(const char *device, const struct in_addr *gw_ip);

int virt_add_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip);
int virt_delete_vroute(uint32_t dest, uint32_t netmask, uint32_t node_ip);

int virt_local_prio(int local_dev, int prio);
int virt_remote_prio(const struct in_addr *remote_node, const struct in_addr *remote_addr, int prio);

int virt_local_bandwidth_hint(int local_dev, long bandwidth);
int virt_remote_bandwidth_hint(__be32 remote_addr, long bandwidth);

int add_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);
int delete_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);

int virt_set_notx_flag(const char *device);
int virt_clear_notx_flag(const char *device);

#endif //_KERNEL_H_

