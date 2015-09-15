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
#include "remote_node.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "format.h"
#include "util.h"

static int _rchan_message(const char *wiroot_ip, unsigned short wiroot_port,
                          const char *request, int request_len, const char *interface,
                          char *response, int response_len);
static int _all_ife_rchan_message(const char *wiroot_ip, unsigned short wiroot_port,
                                  const char *request, int request_len, char *response, int response_len);

static struct lease_info latest_lease = {
    .priv_ip = IPADDR_IPV4_ZERO,
    .unique_id = 0,
};

void ntoh_lease(struct lease_info* lease, struct lease_info *dst)
{
    copy_ipaddr(&lease->priv_ip, &dst->priv_ip);
    dst->priv_subnet_size = lease->priv_subnet_size;
    dst->client_subnet_size = lease->client_subnet_size;
    dst->time_limit = ntohl(lease->time_limit);
    dst->unique_id = ntohs(lease->unique_id);
    /* Add a remote node that will represent the controller */
    memcpy(&dst->cinfo, &lease->cinfo, sizeof(struct controller_info));
}

int fill_rchanhdr(char *buffer, uint8_t type, int send_pub_key)
{
    int offset = 0;
    char node_id[NODE_ID_MAX_BIN_LEN];
    int node_id_len = get_node_id_bin(node_id, sizeof(node_id));
    if(node_id_len < 0) {
        DEBUG_MSG("get_node_id_bin failed");
        return FAILURE;
    }

    struct rchanhdr *rchanhdr = (struct rchanhdr *)buffer;
    offset += sizeof(struct rchanhdr);

    rchanhdr->version = get_wirover_version();
    rchanhdr->type = type;
    rchanhdr->id_len = node_id_len;

    /* Copy node_id into the packet. */
    memcpy(buffer + offset, node_id, node_id_len);
    offset += node_id_len;

    /* Copy the public key into the packet. */
    int pub_key_size = 0;
    if(send_pub_key) {
        char pub_key[1024];
        pub_key_size = read_public_key(pub_key, sizeof(pub_key));
        if(pub_key_size == FAILURE)
        {
            DEBUG_MSG("Could not read public key");
            pub_key_size = 0;
        }
        else
        {
            memcpy(buffer + offset, pub_key, pub_key_size);
            offset += pub_key_size;
        }
    }
    rchanhdr->pub_key_len = pub_key_size;

    return offset;
}
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

    offset = fill_rchanhdr(buffer, RCHAN_REGISTER_CONTROLLER, 1);
    if(offset < 0)
        goto free_and_err_out;

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

    result = _rchan_message(wiroot_ip, wiroot_port, buffer, offset, 0, (char *)&response, sizeof(struct rchan_response));
    if(result < 0) {
        DEBUG_MSG("Failed to obtain lease from root server");
        goto free_and_err_out;
    }

    ntoh_lease(&response.lease, lease);
    DEBUG_MSG("Got client subnet size of %d", lease->client_subnet_size);

    memcpy(&latest_lease, lease, sizeof(latest_lease));

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

    offset = fill_rchanhdr(buffer, RCHAN_REGISTER_GATEWAY, 1);
    if(offset < 0)
        goto free_and_err_out;

    struct rchan_gwreg *gwreg = (struct rchan_gwreg *)(buffer + offset);
    offset += sizeof(struct rchan_gwreg);

    gwreg->latitude = NAN;
    gwreg->longitude = NAN;

    struct rchan_response response;

    int lease_obtained = _all_ife_rchan_message(wiroot_ip, wiroot_port, buffer, offset,
        (char *)&response, sizeof(struct rchan_response));

    if(lease_obtained == FAILURE) {
        DEBUG_MSG("Failed to obtain lease");
        goto free_and_err_out;
    }


    ntoh_lease(&response.lease, lease);

    struct interface *cont_ife = alloc_interface(lease->cinfo.unique_id);
    ipaddr_to_ipv4(&lease->cinfo.pub_ip, &cont_ife->public_ip.s_addr);
    cont_ife->data_port = lease->cinfo.data_port;
    cont_ife->control_port = lease->cinfo.control_port;

    struct remote_node *node = alloc_remote_node();
    node->head_interface = cont_ife;
    node->unique_id = lease->cinfo.unique_id;
    add_remote_node(node);

    memcpy(&latest_lease, lease, sizeof(latest_lease));

    free(buffer);
    return 0;

free_and_err_out:
    free(buffer);
err_out:
    return -1;
}
#endif /* GATEWAY */
static int _all_ife_rchan_message(const char *wiroot_ip, unsigned short wiroot_port,
                                  const char *request, int request_len, char *response, int response_len)
{
    obtain_read_lock(&interface_list_lock);
    struct interface_copy *iface_list = NULL;
    int num_ifaces = copy_all_interfaces(interface_list, &iface_list);
    release_read_lock(&interface_list_lock);

    if(num_ifaces <= 0) {
        DEBUG_MSG("Cannot request lease, no interfaces available");
        return FAILURE;
    }

    int i;
    int rtn = FAILURE;

    for(i = 0; i < num_ifaces; i++) {
        const char *ifname = iface_list[i].name;

        if(_rchan_message(wiroot_ip, wiroot_port, request, request_len, 
            ifname, response, response_len) == SUCCESS) {
                rtn = SUCCESS;
                break;
        }
    }

    if(iface_list) {
        free(iface_list);
    }
    return rtn;
}
/*
* Attempt to obtain a lease from the root server.  This will bind to the given
* interface if interface is not null.  If successful, it returns 0 and fills
* in the response, otherwise it returns -1 and the contents of response are
* undefined.
*/
static int _rchan_message(const char *wiroot_ip, unsigned short wiroot_port,
                          const char *request, int request_len, const char *interface,
                          char *response, int response_len)
{ 
    int result;

    struct timeval timeout;
    timeout.tv_sec  = RCHAN_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    struct sockaddr_storage dest;
    build_sockaddr(wiroot_ip, wiroot_port, &dest);
    int sockfd = tcp_active_open(&dest, interface, &timeout);
    if(sockfd == -1) {
        DEBUG_MSG("failed to connect to wiroot server");
        goto err_out;
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval))) {
        ERROR_MSG("Could not set timeout");
        goto close_and_err_out;
    }
    result = send(sockfd, request, request_len, 0);
    if(result <= 0) {
        ERROR_MSG("error sending root channel message");
        goto close_and_err_out;
    }

    result = recv(sockfd, response, response_len, 0);
    if(result <= 0) {
        ERROR_MSG("error receiving root channel response");
        goto close_and_err_out;
    } else if(result < MIN_RESPONSE_LEN) {
        if(response[0] != -1)
            DEBUG_MSG("root channel response was too small to be valid");
        goto close_and_err_out;
    }

    close(sockfd);
    return SUCCESS;

close_and_err_out:
    close(sockfd);
err_out:
    return FAILURE;
}

int request_pubkey(const char *wiroot_ip, unsigned short wiroot_port,
                   uint16_t remote_id, char *pub_key, int pub_key_len)
{
    char buffer[BUFSIZ];
    int offset = 0;
    offset = fill_rchanhdr(buffer, RCHAN_ACCESS_REQUEST, 0);

    memcpy(buffer + offset, &remote_id, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    return _all_ife_rchan_message(wiroot_ip, wiroot_port, buffer, offset, pub_key, pub_key_len);
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
unsigned short get_controller_control_port()
{
    return ntohs(latest_lease.cinfo.control_port);
}

/*
* It is recommended that your buffer be at least INET6_ADDRSTRLEN bytes in
* size.
*/
int get_controller_privip(char *dest, int dest_len)
{
    ipaddr_to_string(&latest_lease.cinfo.priv_ip, dest, dest_len);
    return SUCCESS;
}

struct interface *get_controller_ife()
{
    struct remote_node *controller = lookup_remote_node_by_id(get_lease_info()->cinfo.unique_id);
    if(controller == NULL){
        DEBUG_MSG("Returning null");
        return NULL;
    }
    
    return controller->head_interface;
}


