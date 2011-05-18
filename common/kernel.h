#ifndef _KERNEL_H_
#define _KERNEL_H_

#define SIOCVIRTENSLAVE   (SIOCDEVPRIVATE + 0)
#define SIOCVIRTRELEASE   (SIOCDEVPRIVATE + 1)
#define SIOCVIRTSETHWADDR (SIOCDEVPRIVATE + 2)
#define SIOCVIRTSETPROXY  (SIOCDEVPRIVATE + 3)
#define SIOCVIRTSETGWADDR (SIOCDEVPRIVATE + 4)

#define VIRT_PROC_REMOTE_ADD     0
#define VIRT_PROC_REMOTE_DELETE  1

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

int setup_virtual_interface(const char *ip);

int kernel_set_controller(const struct sockaddr_in* addr);
int kernel_enslave_device(const char* device);
int kernel_release_device(const char* device);

int virt_add_remote_node(const struct in_addr *priv_ip, 
        const struct in_addr *netmask);
int virt_add_remote_link(const struct in_addr *priv_ip,
        const struct in_addr *pub_ip, unsigned short data_port);

#endif //_KERNEL_H_

