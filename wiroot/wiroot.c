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

#include "contchan.h"
#include "controllers.h"
#include "debug.h"
#include "lease.h"
#include "sockets.h"
#include "utlist.h"

const unsigned int  MTU = 1500;
const char*         CONFIG_FILENAME = "wiroot.conf";
const int           MAX_CONTROLLERS = 3;
const int           CLEANUP_INTERVAL = 5; // seconds between calling remove_stale_leases()

/*
 * STRUCT CLIENT
 *
 * Stores information about a connected client.  This is not to be confused
 * with outstanding leases.  Client connections are very short-lived.
 */
struct client {
    int                 fd;
    struct sockaddr_in  addr;
    socklen_t           addr_len;

    //only to be modified by utlist
    struct client*      next;
    struct client*      prev;
};

// This default value will be writted during configuration.
static unsigned short WIROOT_PORT = 8082;

// Doubly-linked list of connected clients
static struct client* clients_head = 0;

static config_t       config;
static char           msg_buffer[1024];

static int  configure_wiroot(const char* filename);
static void handle_connection(int server_sock);
static void handle_incoming(struct client* client);
static void handle_gateway_config(struct client* client, const char* packet, int length);
static void handle_controller_config(struct client* client, const char* packet, int length);
static void handle_disconnection(struct client* client);
static void fdset_add_clients(fd_set* set, int* max_fd);
static int  find_config_file(char* filename, int length);

int main(int argc, char* argv[])
{
    int server_sock;
    int result;

    result = configure_wiroot(CONFIG_FILENAME);
    if(result == -1) {
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
        fdset_add_clients(&read_set, &max_fd);

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
        } else {
            if(FD_ISSET(server_sock, &read_set)) {
                handle_connection(server_sock);
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

    config_destroy(&config);
    close(server_sock);
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
    char buffer[1024];

    result = find_config_file(buffer, sizeof(buffer));
    if(!result) {
        DEBUG_MSG("Failed to find a config file for wiroot");
        return -1;
    }

    snprintf(msg_buffer, sizeof(msg_buffer),
             "Found config file: %s", buffer);
    DEBUG_MSG(msg_buffer);

    result = config_read_file(&config, buffer);
    if(result == CONFIG_FALSE) {
        snprintf(msg_buffer, sizeof(msg_buffer),
                 "Failed to read config file: %s",
                 config_error_text(&config));
        DEBUG_MSG(msg_buffer);
    }

    int port;
    result = config_lookup_int(&config, "server.port", &port);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("Error reading server.port from config file");
    } else if(port < 0 || port > 0x0000FFFF) {
        DEBUG_MSG("server.port in config file is out of range");
    } else {
        WIROOT_PORT = (unsigned short)port;
    }

    result = read_lease_config(&config);
    if(result == -1) {
        DEBUG_MSG("read_lease_config() failed");
        return -1;
    }

    return 0;
}

/*
 * HANDLE CONNECTION
 *
 * Accepts a client connection attempt and adds it to the linked list of
 * clients.
 */
static void handle_connection(int server_sock)
{
    struct client* client = (struct client*)malloc(sizeof(struct client));
    assert(client);

    client->addr_len = sizeof(client->addr);
    client->fd = accept(server_sock, (struct sockaddr*)&client->addr, &client->addr_len);
    if(client->fd == -1) {
        ERROR_MSG("accept() failed");
        free(client);
        return;
    }

    // All of our sockets will be non-blocking since they are handled by a
    // single thread, and we cannot have one evil client hold up the rest.
    set_nonblock(client->fd, 1);

    DL_APPEND(clients_head, client);
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

    bytes = recv(client->fd, packet, sizeof(packet), 0);
    if(bytes == -1) {
        ERROR_MSG("recv() failed");
        return;
    } else if(bytes == 0) {
        handle_disconnection(client);
        return;
    } else if(bytes < MIN_REQUEST_LEN) {
        DEBUG_MSG("Client packet was too small to be a valid request.");
        return;
    }

    uint8_t type = packet[0];
    switch(type) {
        case CCHAN_GATEWAY_CONFIG:
            handle_gateway_config(client, packet, bytes);
            break;
        case CCHAN_CONTROLLER_CONFIG:
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
    struct cchan_request* request = (struct cchan_request*)packet;

    const struct lease* lease;
    lease = grant_lease(request->hw_addr, sizeof(request->hw_addr));
    
    char response_buffer[MTU];
    struct cchan_response* response = (struct cchan_response*)response_buffer;
    response->type = request->type;

    // Any controller IPs will be added to the packet after this structure.
    int response_index = sizeof(struct cchan_response);

    if(lease) {
        struct node* node_list[MAX_CONTROLLERS];
        response->controllers = assign_controllers(node_list, MAX_CONTROLLERS, 
                request->latitude, request->longitude);

        int i;
        for(i = 0; i < response->controllers; i++) {
            struct cchan_controller_info* cinfo =
                    (struct cchan_controller_info*)&response_buffer[response_index];
            cinfo->priv_ip = node_list[i]->priv_ip;
            cinfo->pub_ip = node_list[i]->pub_ip;
            response_index += sizeof(struct cchan_controller_info);
        }

        response->priv_ip = lease->ip;
        response->lease_time = (lease->end - lease->start);
    }

    int bytes = send(client->fd, response, response_index, 0);
    if(bytes < sizeof(response)) {
        DEBUG_MSG("Failed to send lease response");
    }
}

/*
 * HANDLE CONTROLLER CONFIG
 *
 * Processes a request from a controller and sends a response.
 */
static void handle_controller_config(struct client* client, const char* packet, int length) {
    struct cchan_request* request = (struct cchan_request*)packet;

    const struct lease* lease;
    lease = grant_lease(request->hw_addr, sizeof(request->hw_addr));
    
    char response_buffer[MTU];
    struct cchan_response* response = (struct cchan_response*)response_buffer;
    response->type = request->type;

    if(lease) {
        uint32_t pub_ip = client->addr.sin_addr.s_addr;
        add_controller(lease->ip, pub_ip, request->latitude, request->longitude);

        response->priv_ip = lease->ip;
        response->lease_time = (lease->end - lease->start);
        response->controllers = 0;
    }

    int bytes = send(client->fd, response, sizeof(struct cchan_response), 0);
    if(bytes < sizeof(response)) {
        DEBUG_MSG("Failed to send lease response");
    }
}

/*
 * HANDLE DISCONNECTION
 *
 * Removes a client from the linked list, closes its socket, and frees its
 * memory.
 */
static void handle_disconnection(struct client* client)
{
    assert(client);

    close(client->fd);
    client->fd = -1;

    DL_DELETE(clients_head, client);
    free(client);
}

/*
 * FDSET ADD CLIENTS
 *
 * Adds every client in the list to an fd_set and updates the max_fd value.
 */
static void fdset_add_clients(fd_set* set, int* max_fd)
{
    assert(set && max_fd);

    struct client* client;
    DL_FOREACH(clients_head, client) {
        FD_SET(client->fd, set);

        if(client->fd > *max_fd) {
            *max_fd = client->fd;
        }
    }
}

/*
 * FIND CONFIG FILE
 *
 * Checks the current directory and the system /etc directory for wiroot.conf.
 *
 * On success find_config_file() returns 1 and filename is valid.  On
 * failure it returns 0, and filename is not valid.
 */
static int find_config_file(char* filename, int length)
{
    int result;

    // First check if the file is in the current directory
    snprintf(filename, length, "%s", CONFIG_FILENAME);
    result = access(filename, R_OK);
    if(result == 0) {
        return 1;
    }

    // Check for a system config file
    snprintf(filename, length, "/etc/%s", CONFIG_FILENAME);
    result = access(filename, R_OK);
    if(result == 0) {
        return 1;
    }

    return 0;
}

