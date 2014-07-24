#include <errno.h>
#include <libconfig.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

#include "config.h"
#include "configuration.h"
#include "contchan.h"
#include "controllers.h"
#include "database.h"
#include "debug.h"
#include "lease.h"
#include "rootchan.h"
#include "sockets.h"
#include "utlist.h"
#include "format.h"
#include "timing.h"

const int CLEANUP_INTERVAL = 5; // seconds between calling remove_stale_leases()
const int DB_MIN_RETRY_DELAY = 1;
const int DB_MAX_RETRY_DELAY = 64;

// This default value will be writted during configuration.
static unsigned short WIROOT_PORT = 8088;
static int            CLIENT_TIMEOUT = 5;

// Doubly-linked list of connected clients
static struct client* clients_head = 0;

// Whether or not to automatically grant new privileges.
static int auto_grant = 0;

static int  configure_wiroot(const char* filename);
static void handle_incoming(struct client* client);
static void handle_gateway_config(struct client* client, const char* packet, int length);
static void handle_controller_config(struct client* client, const char* packet, int length);
static void handle_access_request(struct client *client, const char *packet, int length);

static int log_access_request(int type, const char *node_id, 
        struct client *client, int result);

int main(int argc, char* argv[])
{
    int server_sock;
    int result;

    signal(SIGSEGV, segfault_handler);

    printf("WiRover version %d.%d.%d\n", WIROVER_VERSION_MAJOR, 
            WIROVER_VERSION_MINOR, WIROVER_VERSION_REVISION);

    result = configure_wiroot(CONFIG_FILENAME);
    if(result == -1) {
        return 1;
    }

    int retry_delay = DB_MIN_RETRY_DELAY;
    while(db_connect() < 0) {
        DEBUG_MSG("failed to connect to mysql database, will retry in %d seconds", retry_delay);
        retry_delay = exp_delay(retry_delay, DB_MIN_RETRY_DELAY, DB_MAX_RETRY_DELAY);
    }

    server_sock = tcp_passive_open(WIROOT_PORT, SOMAXCONN);
    if(server_sock == -1) {
        DEBUG_MSG("failed to open server socket");
        return 1;
    }
    set_nonblock(server_sock, 1);

    while(1) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(server_sock, &read_set);

        struct timeval timeout;
        timeout.tv_sec = CLEANUP_INTERVAL;
        timeout.tv_usec = 0;

        int max_fd = server_sock;
        fdset_add_clients(clients_head, &read_set, &max_fd);

        result = select(max_fd+1, &read_set, 0, 0, &timeout);
        if(result == -1) {
            if(errno != EINTR) {
                ERROR_MSG("select failed");
                return 1;
            }
        } else if(result == 0) {
            // If select timed out, we must be idle, so it is a good time for
            // cleanup.
            remove_stale_leases();
            remove_idle_clients(&clients_head, CLIENT_TIMEOUT);
        } else {
            if(FD_ISSET(server_sock, &read_set)) {
                handle_connection(&clients_head, server_sock);
            }

            struct client* client;
            struct client* tmp;

            //DL_FOREACH_SAFE lets us delete elements while traversing the list.
            DL_FOREACH_SAFE(clients_head, client, tmp) {
                if(FD_ISSET(client->fd, &read_set)) {
                    handle_incoming(client);
                }
            }
        }
    }

    close(server_sock);
    db_disconnect();
    close_config();
}

/*
 * CONFIGURE WIROOT
 *
 * Opens the wiroot configuration file and makes all appropriate changes.
 *
 * Returns -1 on failure and 0 on success.
 */
static int configure_wiroot(const char* filename)
{
    int result;

    const config_t* config = get_config();
    if(!config) {
        DEBUG_MSG("Warning: wiroot config file was not found\n");
        return 0;
    }

    int port;
    result = config_lookup_int_compat(config, "server.port", &port);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("Error reading server.port from config file");
    } else if(port < 0 || port > 0x0000FFFF) {
        DEBUG_MSG("server.port in config file is out of range");
    } else {
        WIROOT_PORT = (unsigned short)port;
    }
    
    int timeout;
    result = config_lookup_int_compat(config, "server.client-timeout", &timeout);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("Error reading server.client-timeout from config file");
    } else if(timeout < 0) {
        DEBUG_MSG("server.client-timeout in config file is out of range");
    } else {
        CLIENT_TIMEOUT = timeout;
    }

    result = read_lease_config(config);
    if(result == -1) {
        DEBUG_MSG("read_lease_config() failed");
        return -1;
    }

    config_lookup_bool(config, "auto-grant", &auto_grant);

    return 0;
}

/*
 * HANDLE INCOMING
 *
 * Receives a packet from a client and dispatches it to an appropriate packet
 * handling function.
 */
static void handle_incoming(struct client* client)
{
    int bytes;
    char packet[MTU];

    assert(client);
    client->last_active = time(0);

    bytes = recv(client->fd, packet, sizeof(packet), 0);
    if(bytes == -1) {
        ERROR_MSG("recv() failed");
        return;
    } else if(bytes == 0) {
        handle_disconnection(&clients_head, client);
        return;
    } else if(bytes < sizeof(struct rchanhdr)) {
        DEBUG_MSG("Client packet was too small to be a valid request.");
        return;
    }

    uint8_t type = packet[0];
    switch(type) {
        case RCHAN_REGISTER_GATEWAY:
            handle_gateway_config(client, packet, bytes);
            break;
        case RCHAN_REGISTER_CONTROLLER:
            handle_controller_config(client, packet, bytes);
            break;
        case RCHAN_ACCESS_REQUEST:
            handle_access_request(client, packet, bytes);
            break;
    }
}

/*
 * HANDLE GATEWAY CONFIG
 *
 * Processes a request from a gateway and sends a response.
 */
static void handle_gateway_config(struct client* client, const char* packet, int length) {
    struct rchanhdr *rchanhdr = (struct rchanhdr *)packet;
    unsigned offset = sizeof(struct rchanhdr);

    const char *node_id = packet + offset;
    offset += rchanhdr->id_len;

    struct rchan_gwreg *gwreg = (struct rchan_gwreg *)(packet + offset);
    offset += sizeof(struct rchan_gwreg);

    if(offset > length) {
        DEBUG_MSG("Gateway registration packet was too short: %u bytes, expected %d",
                length, offset);
        return;
    }
    
    char node_id_hex[NODE_ID_MAX_HEX_LEN+1];
    int result = bin_to_hex(node_id, rchanhdr->id_len,
            node_id_hex, sizeof(node_id_hex));
    if(result < 0) {
        DEBUG_MSG("Conversion of node_id failed");
        return;
    }

    int unique_id = db_check_privilege(node_id_hex, PRIV_REG_GATEWAY);
    if(unique_id <= 0 && auto_grant)
        unique_id = db_grant_privilege(node_id_hex, PRIV_REG_GATEWAY);

    if(unique_id > 0) {
        const struct lease* lease;
        lease = grant_lease(unique_id);
      
        struct rchan_response response;
        response.type = rchanhdr->type;
        response.unique_id = htons(unique_id);

        if(lease) {
            struct controller* controller_list[MAX_CONTROLLERS];
            response.controllers = assign_controllers(controller_list, MAX_CONTROLLERS, 
                    gwreg->latitude, gwreg->longitude);

            int i;
            for(i = 0; i < response.controllers && i < MAX_CONTROLLERS; i++) {
                copy_ipaddr(&controller_list[i]->priv_ip, &response.cinfo[i].priv_ip);
                copy_ipaddr(&controller_list[i]->pub_ip, &response.cinfo[i].pub_ip);
                response.cinfo[i].data_port = controller_list[i]->data_port;
                response.cinfo[i].control_port = controller_list[i]->control_port;
                response.cinfo[i].unique_id = controller_list[i]->unique_id;
            }

            copy_ipaddr(&lease->ip, &response.priv_ip);
            response.priv_subnet_size = get_lease_subnet_size();
            response.lease_time = htonl(lease->end - lease->start);
        }

        const unsigned int response_len = MIN_RESPONSE_LEN +
                response.controllers * sizeof(struct controller_info);

        int bytes = send(client->fd, &response, response_len, 0);
        if(bytes < response_len) {
            DEBUG_MSG("Failed to send lease response");
        }
        
        log_access_request(PRIV_REG_GATEWAY, node_id_hex, 
                client, RCHAN_RESULT_SUCCESS);
    } else {
        struct rchan_response response;
        memset(&response, 0, sizeof(response));
        response.type = RCHAN_REGISTRATION_DENIED;

        const unsigned response_len = MIN_RESPONSE_LEN;

        int bytes = send(client->fd, &response, response_len, 0);
        if(bytes < response_len) {
            DEBUG_MSG("Failed to send lease response");
        }

        log_access_request(PRIV_REG_GATEWAY, node_id_hex,
                client, RCHAN_RESULT_DENIED);
    }
}

/*
 * HANDLE CONTROLLER CONFIG
 *
 * Processes a request from a controller and sends a response.
 */
static void handle_controller_config(struct client* client, const char* packet, int length) {
    struct rchanhdr *rchanhdr = (struct rchanhdr *)packet;
    unsigned offset = sizeof(struct rchanhdr);
    
    const char *node_id = packet + offset;
    offset += rchanhdr->id_len;

    struct rchan_ctrlreg *ctrlreg = (struct rchan_ctrlreg *)(packet + offset);
    offset += sizeof(struct rchan_ctrlreg);

    if(offset > length) {
        DEBUG_MSG("Controller registration packet was too short: %u bytes, expected %d",
                length, offset);
        return;
    }

    char node_id_hex[NODE_ID_MAX_HEX_LEN+1];
    int result = bin_to_hex(node_id, rchanhdr->id_len,
            node_id_hex, sizeof(node_id_hex));
    if(result < 0) {
        DEBUG_MSG("Conversion of node_id failed");
        return;
    }

    int unique_id = db_check_privilege(node_id_hex, PRIV_REG_CONTROLLER);
    if(unique_id <= 0 && auto_grant)
        unique_id = db_grant_privilege(node_id_hex, PRIV_REG_CONTROLLER);

    if(unique_id > 0) {
        const struct lease* lease;
        lease = grant_lease(unique_id);
        
        char response_buffer[MTU];
        struct rchan_response* response = (struct rchan_response*)response_buffer;
        response->type = rchanhdr->type;
        response->unique_id = htons(unique_id);

        if(lease) {
            ipaddr_t ctrl_ip;

            switch(ctrlreg->family) {
                case RCHAN_USE_SOURCE:
                    sockaddr_to_ipaddr((const struct sockaddr *)&client->addr, &ctrl_ip);
                    break;
                case AF_INET:
                {
                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_addr.s_addr = ctrlreg->addr.ip4;
                    sockaddr_to_ipaddr((const struct sockaddr *)&sin, &ctrl_ip);
                    break;
                }
                case AF_INET6:
                {
                    struct sockaddr_in6 sin;
                    sin.sin6_family = AF_INET6;
                    memcpy(sin.sin6_addr.s6_addr, ctrlreg->addr.ip6, 
                            sizeof(sin.sin6_addr.s6_addr));
                    sockaddr_to_ipaddr((const struct sockaddr *)&sin, &ctrl_ip);
                    break;
                }
                default:
                    DEBUG_MSG("Unrecognized address family: %hu", ctrlreg->family);
                    return;
            }

            add_controller(unique_id, &lease->ip, &ctrl_ip, ctrlreg->data_port, ctrlreg->control_port,
                    ctrlreg->latitude, ctrlreg->longitude);

            char p_ip[INET6_ADDRSTRLEN];
            ipaddr_to_string(&ctrl_ip, p_ip, sizeof(p_ip));

            DEBUG_MSG("Controller registered as %s data %hu control %hu",
                    p_ip, ntohs(ctrlreg->data_port), ntohs(ctrlreg->control_port));

            copy_ipaddr(&lease->ip, &response->priv_ip);
            response->priv_subnet_size = get_lease_subnet_size();
            response->lease_time = htonl(lease->end - lease->start);
            response->controllers = 0;
        }

        int bytes = send(client->fd, response, sizeof(struct rchan_response), 0);
        if(bytes < sizeof(response)) {
            DEBUG_MSG("Failed to send lease response");
        }

        log_access_request(PRIV_REG_CONTROLLER, node_id_hex, 
                client, RCHAN_RESULT_SUCCESS);
    } else {
        struct rchan_response response;
        memset(&response, 0, sizeof(response));
        response.type = RCHAN_REGISTRATION_DENIED;

        const unsigned response_len = MIN_RESPONSE_LEN;

        int bytes = send(client->fd, &response, response_len, 0);
        if(bytes < response_len) {
            DEBUG_MSG("Failed to send lease response");
        }
    
        log_access_request(PRIV_REG_CONTROLLER, node_id_hex, 
                client, RCHAN_RESULT_DENIED);
    }
}

/*
 * Process an access request message.
 */
static void handle_access_request(struct client *client, const char *packet, int length) {
    struct rchanhdr *rchanhdr = (struct rchanhdr *)packet;
    unsigned offset = sizeof(struct rchanhdr);

    const char *node_id = packet + offset;
    offset += rchanhdr->id_len;

    if(offset > length) {
        DEBUG_MSG("Access request packet was too short: %u bytes, expected %d",
                length, offset);
        return;
    }
    
    char node_id_hex[NODE_ID_MAX_HEX_LEN+1];
    int result = bin_to_hex(node_id, rchanhdr->id_len,
            node_id_hex, sizeof(node_id_hex));
    if(result < 0) {
        DEBUG_MSG("Conversion of node_id failed");
        return;
    }

    /* TODO: We need to get a public key from the client and store it somewhere. */
}

static int log_access_request(int type, const char *node_id, 
        struct client *client, int result)
{
    char src_ip[INET6_ADDRSTRLEN];
    int ret;

    ret = getnameinfo((struct sockaddr *)&client->addr, client->addr_len, 
            src_ip, sizeof(src_ip), NULL, 0, NI_NUMERICHOST);
    if(ret != 0) {
        DEBUG_MSG("getnameinfo failed: %d", ret);
        return -1;
    }

    return db_add_access_request(type, node_id, src_ip, result);
}
