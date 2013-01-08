#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "config.h"
#include "configuration.h"
#include "debug.h"
#include "interface.h"
#include "netlink.h"
#include "pathperf.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "format.h"

static int _obtain_lease(const char *wiroot_ip, unsigned short wiroot_port,
        const char *request, int request_len, const char *interface,
        struct rchan_response *response);

static struct lease_info latest_lease = {
    .priv_ip = IPADDR_IPV4_ZERO,
    .unique_id = 0,
};

#ifdef CONTROLLER
/* 
 * register_controller - Register a controller with the root server.
 */
int register_controller(struct lease_info *lease, const char *wiroot_ip, 
        unsigned short wiroot_port, unsigned short data_port, unsigned short control_port)
{
    char *buffer;
    int result;
    int offset = 0;

    buffer = malloc(BUFSIZ);
    if(!buffer) {
        DEBUG_MSG("Out of memory.");
        goto err_out;
    }

    memset(buffer, 0, BUFSIZ);
    
    char node_id[NODE_ID_MAX_BIN_LEN];
    int node_id_len = get_node_id_bin(node_id, sizeof(node_id));
    if(node_id_len < 0) {
        DEBUG_MSG("get_node_id_bin failed");
        goto free_and_err_out;
    }

    struct rchanhdr *rchanhdr = (struct rchanhdr *)buffer;
    offset += sizeof(struct rchanhdr);

    rchanhdr->type = RCHAN_REGISTER_CONTROLLER;
    rchanhdr->id_len = node_id_len;

    /* Copy node_id into the packet. */
    memcpy(buffer + offset, node_id, node_id_len);
    offset += node_id_len;

    struct rchan_ctrlreg *ctrlreg = (struct rchan_ctrlreg *)(buffer + offset);
    offset += sizeof(struct rchan_ctrlreg);

    const char *register_address = get_register_address();
    if(!register_address || strlen(register_address) == 0) {
        ctrlreg->family = RCHAN_USE_SOURCE;
    } else {
        struct sockaddr_in sin;
        result = resolve_address(register_address, 
                (struct sockaddr *)&sin, sizeof(sin));
        if(result < 0) {
            DEBUG_MSG("Failed to resolve address string: %s", register_address);
            goto free_and_err_out;
        } else {
            ctrlreg->family = AF_INET;
            ctrlreg->addr.ip4 = sin.sin_addr.s_addr;
        }
    }

    ctrlreg->data_port = htons(data_port);
    ctrlreg->control_port = htons(control_port);
    ctrlreg->latitude = NAN;
    ctrlreg->longitude = NAN;

    struct rchan_response response;

    result = _obtain_lease(wiroot_ip, wiroot_port, buffer, offset, 0, &response);
    if(result < 0) {
        DEBUG_MSG("Failed to obtain lease from root server");
        goto free_and_err_out;
    }
    
    copy_ipaddr(&response.priv_ip, &lease->priv_ip);
    lease->priv_subnet_size = response.priv_subnet_size;
    lease->time_limit = ntohl(response.lease_time);
    lease->unique_id = ntohs(response.unique_id);
    lease->controllers = 0;
   
    memcpy(&latest_lease, lease, sizeof(latest_lease));

    write_path_list();

    free(buffer);
    return 0;

free_and_err_out:
    free(buffer);
err_out:
    return -1;
}
#endif /* CONTROLLER */

#ifdef GATEWAY
/* 
 * register_gateway - Register a gateway with the root server.
 */
int register_gateway(struct lease_info *lease, const char *wiroot_ip, 
        unsigned short wiroot_port)
{
    char *buffer;
    int offset = 0;

    buffer = malloc(BUFSIZ);
    if(!buffer) {
        DEBUG_MSG("Out of memory.");
        goto err_out;
    }

    memset(buffer, 0, BUFSIZ);
    
    char node_id[NODE_ID_MAX_BIN_LEN];
    int node_id_len = get_node_id_bin(node_id, sizeof(node_id));
    if(node_id_len < 0) {
        DEBUG_MSG("get_node_id_bin failed");
        goto free_and_err_out;
    }

    struct rchanhdr *rchanhdr = (struct rchanhdr *)buffer;
    offset += sizeof(struct rchanhdr);

    rchanhdr->type = RCHAN_REGISTER_GATEWAY;
    rchanhdr->id_len = node_id_len;

    /* Copy node_id into the packet. */
    memcpy(buffer + offset, node_id, node_id_len);
    offset += node_id_len;

    struct rchan_gwreg *gwreg = (struct rchan_gwreg *)(buffer + offset);
    offset += sizeof(struct rchan_gwreg);

    gwreg->latitude = NAN;
    gwreg->longitude = NAN;

    obtain_read_lock(&interface_list_lock);
    struct interface_copy *iface_list;
    int num_ifaces = copy_all_interfaces(interface_list, &iface_list);
    release_read_lock(&interface_list_lock);

    if(num_ifaces <= 0) {
        DEBUG_MSG("Cannot request lease, no interfaces available");
        goto free_and_err_out;
    }

    int i;
    int lease_obtained = 0;
    struct rchan_response response;

    for(i = 0; i < num_ifaces; i++) {
        const char *ifname = iface_list[i].name;

        if(_obtain_lease(wiroot_ip, wiroot_port, buffer, offset, 
                    ifname, &response) == 0) {
            lease_obtained = 1;
            break;
        }
    }

    free(iface_list);

    if(!lease_obtained) {
        DEBUG_MSG("Failed to obtain lease, %d interfaces tried", num_ifaces);
        goto free_and_err_out;
    }

    copy_ipaddr(&response.priv_ip, &lease->priv_ip);
    lease->priv_subnet_size = response.priv_subnet_size;
    lease->time_limit = ntohl(response.lease_time);
    lease->unique_id = ntohs(response.unique_id);
    lease->controllers = response.controllers;

    if(lease->controllers > 0) {
        if(lease->controllers > MAX_CONTROLLERS)
            lease->controllers = MAX_CONTROLLERS;

        const int copy_size = lease->controllers * sizeof(struct controller_info);

        memcpy(lease->cinfo, response.cinfo, copy_size);
    }
    
    memcpy(&latest_lease, lease, sizeof(latest_lease));

    write_path_list();

    free(buffer);
    return 0;

free_and_err_out:
    free(buffer);
err_out:
    return -1;
}
#endif /* GATEWAY */

/*
 * Attempt to obtain a lease from the root server.  This will bind to the given
 * interface if interface is not null.  If successful, it returns 0 and fills
 * in the response, otherwise it returns -1 and the contents of response are
 * undefined.
 */
static int _obtain_lease(const char *wiroot_ip, unsigned short wiroot_port,
        const char *request, int request_len, const char *interface,
        struct rchan_response *response)
{ 
    int result;

    struct timeval timeout;
    timeout.tv_sec  = RCHAN_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    int sockfd = tcp_active_open(wiroot_ip, wiroot_port, interface, &timeout);
    if(sockfd == -1) {
        DEBUG_MSG("failed to connect to wiroot server");
        goto err_out;
    }

    result = send(sockfd, request, request_len, 0);
    if(result <= 0) {
        ERROR_MSG("error sending lease request");
        goto close_and_err_out;
    }

    result = recv(sockfd, response, sizeof(struct rchan_response), 0);
    if(result <= 0) {
        ERROR_MSG("error receiving lease response");
        goto close_and_err_out;
    } else if(result < MIN_RESPONSE_LEN) {
        DEBUG_MSG("lease response was too small to be valid");
        goto close_and_err_out;
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;

close_and_err_out:
    close(sockfd);
err_out:
    return -1;
}

/*
 * Read cryptographic node_id from a file as a hexadecimal string.
 *
 * Returns the length of the string written to dst or a negative value if an
 * error occurred.
 *
 * If a whitespace character is encountered, the string is truncated at the
 * whitespace character, a null character is written in its place, and only the
 * length up to the whitespace character is returned.
 *
 * The result may not be null-terminated, so the caller must check the return
 * value.
 */
int get_node_id_hex(char *dst, int dst_len)
{
    FILE *file = fopen(NODE_ID_PATH, "r");
    if(!file) {
        ERROR_MSG("Opening %s failed", NODE_ID_PATH);
        return -1;
    }

    int read = fread(dst, sizeof(char), dst_len, file);
    fclose(file);

    int i;
    for(i = 0; i < read; i++) {
        if(!dst[i] || isspace(dst[i])) {
            dst[i] = '\0';
            read = i;
            break;
        }
    }

    return read;
}

/*
 * Read the cryptographic node_id from a file.
 *
 * Returns the size of the node_id in bytes or a negative value if an error
 * occurred.
 */
int get_node_id_bin(char *dst, int dst_len)
{
    char buffer[NODE_ID_MAX_HEX_LEN];

    int hex_len = get_node_id_hex(buffer, sizeof(buffer));
    if(hex_len <= 0) {
        DEBUG_MSG("Failed to read node_id");
        return -1;
    } else if(hex_len > 2 * dst_len) {
        DEBUG_MSG("Length of node_id (0.5 * %d) is too large for buffer (%d)",
                hex_len, dst_len);
        return -1;
    }

    int bin_len = hex_to_bin(buffer, hex_len, dst, dst_len);
    if(bin_len < 0) {
        DEBUG_MSG("Error converting hexadecimal node_id (error code: %d)", bin_len);
        return -1;
    }
    
    return bin_len;
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

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
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
    copy_ipaddr(&latest_lease.priv_ip, dest);
}

const struct lease_info *get_lease_info()
{
    return &latest_lease;
}

uint16_t get_unique_id()
{
    return latest_lease.unique_id;
}

/*
 * Returns controller's data port in host byte order.
 */
unsigned short get_controller_data_port()
{
    if(latest_lease.controllers > 0)
        return ntohs(latest_lease.cinfo[0].data_port);
    else
        return 0;
}

/*
 * Returns controller's data port in host byte order.
 */
unsigned short get_controller_control_port()
{
    if(latest_lease.controllers > 0)
        return ntohs(latest_lease.cinfo[0].control_port);
    else
        return 0;
}

/*
 * It is recommended that your buffer be at least INET6_ADDRSTRLEN bytes in
 * size.
 */
int get_controller_privip(char *dest, int dest_len)
{
    if(latest_lease.controllers > 0) {
        ipaddr_to_string(&latest_lease.cinfo[0].priv_ip, dest, dest_len);
        return 0;
    } else {
        return FAILURE;
    }
}

/*
 * GET CONTROLLER IP
 *
 * It is recommended that your buffer be at least INET6_ADDRSTRLEN bytes in
 * size.
 */
int get_controller_ip(char* dest, int dest_len)
{
    if(latest_lease.controllers > 0) {
        ipaddr_to_string(&latest_lease.cinfo[0].pub_ip, dest, dest_len);
        return 0;
    } else {
        return FAILURE;
    }
}


