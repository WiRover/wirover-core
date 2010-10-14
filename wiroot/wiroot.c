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

#include "configuration.h"
#include "contchan.h"
#include "controllers.h"
#include "database.h"
#include "debug.h"
#include "lease.h"
#include "rootchan.h"
#include "sockets.h"
#include "utlist.h"

const unsigned int  MTU = 1500;
const int           CLEANUP_INTERVAL = 5; // seconds between calling remove_stale_leases()

// This default value will be writted during configuration.
static unsigned short WIROOT_PORT = 8088;
static int            CLIENT_TIMEOUT = 5;

// Doubly-linked list of connected clients
static struct client* clients_head = 0;

static int  configure_wiroot(const char* filename);
static void handle_incoming(struct client* client);
static void handle_gateway_config(struct client* client, const char* packet, int length);
static void handle_controller_config(struct client* client, const char* packet, int length);

int main(int argc, char* argv[])
{
    int server_sock;
    int result;

    result = configure_wiroot(CONFIG_FILENAME);
    if(result == -1) {
        return 1;
    }

    result = db_connect();
    if(result == -1) {
        DEBUG_MSG("failed to connect to mysql database");
        return 1;
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

    int port;
    result = config_lookup_int(config, "server.port", &port);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("Error reading server.port from config file");
    } else if(port < 0 || port > 0x0000FFFF) {
        DEBUG_MSG("server.port in config file is out of range");
    } else {
        WIROOT_PORT = (unsigned short)port;
    }
    
    int timeout;
    result = config_lookup_int(config, "server.client-timeout", &timeout);
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
    } else if(bytes < MIN_REQUEST_LEN) {
        DEBUG_MSG("Client packet was too small to be a valid request.");
        return;
    }

    uint8_t type = packet[0];
    switch(type) {
        case RCHAN_GATEWAY_CONFIG:
            handle_gateway_config(client, packet, bytes);
            break;
        case RCHAN_CONTROLLER_CONFIG:
            handle_controller_config(client, packet, bytes);
            break;
    }
}

/*
 * HANDLE GATEWAY CONFIG
 *
 * Processes a request from a gateway and sends a response.
 */
static void handle_gateway_config(struct client* client, const char* packet, int length) {
    struct rchan_request* request = (struct rchan_request*)packet;

    const struct lease* lease;
    lease = grant_lease(request->hw_addr, sizeof(request->hw_addr));
  
    // Query the database for the unique id of the client
    char p_hw_addr[DB_UNIQUE_ID_LEN+1];
    to_hex_string((const char*)request->hw_addr, sizeof(request->hw_addr), p_hw_addr, sizeof(p_hw_addr));
    unsigned short unique_id = db_get_unique_id(p_hw_addr);

    struct rchan_response response;
    response.type = request->type;
    response.unique_id = htons(unique_id);

    if(lease) {
        struct controller* controller_list[MAX_CONTROLLERS];
        response.controllers = assign_controllers(controller_list, MAX_CONTROLLERS, 
                request->latitude, request->longitude);

        int i;
        for(i = 0; i < response.controllers && i < MAX_CONTROLLERS; i++) {
            copy_ipaddr(&controller_list[i]->priv_ip, &response.cinfo[i].priv_ip);
            copy_ipaddr(&controller_list[i]->pub_ip, &response.cinfo[i].pub_ip);
            response.cinfo[i].base_port = controller_list[i]->base_port;
        }

        copy_ipaddr(&lease->ip, &response.priv_ip);
        response.lease_time = (lease->end - lease->start);
    }

    const unsigned int response_len = MIN_RESPONSE_LEN +
            response.controllers * sizeof(struct controller_info);

    int bytes = send(client->fd, &response, response_len, 0);
    if(bytes < response_len) {
        DEBUG_MSG("Failed to send lease response");
    }
}

/*
 * HANDLE CONTROLLER CONFIG
 *
 * Processes a request from a controller and sends a response.
 */
static void handle_controller_config(struct client* client, const char* packet, int length) {
    struct rchan_request* request = (struct rchan_request*)packet;

    const struct lease* lease;
    lease = grant_lease(request->hw_addr, sizeof(request->hw_addr));
    
    // Query the database for the unique id of the client
    char p_hw_addr[DB_UNIQUE_ID_LEN+1];
    to_hex_string((const char*)request->hw_addr, sizeof(request->hw_addr), p_hw_addr, sizeof(p_hw_addr));
    unsigned short unique_id = db_get_unique_id(p_hw_addr);
    
    char response_buffer[MTU];
    struct rchan_response* response = (struct rchan_response*)response_buffer;
    response->type = request->type;
    response->unique_id = htons(unique_id);

    if(lease) {
        ipaddr_t client_ip;
        sockaddr_to_ipaddr((const struct sockaddr*)&client->addr, &client_ip);

        add_controller(&lease->ip, &client_ip, request->base_port, request->latitude, request->longitude);

        copy_ipaddr(&lease->ip, &response->priv_ip);
        response->lease_time = (lease->end - lease->start);
        response->controllers = 0;
    }

    int bytes = send(client->fd, response, sizeof(struct rchan_response), 0);
    if(bytes < sizeof(response)) {
        DEBUG_MSG("Failed to send lease response");
    }
}

