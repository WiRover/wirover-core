#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "contchan.h"
#include "debug.h"
#include "sockets.h"

const char* WIROOT_ADDRESS = "128.105.22.229";
const unsigned short WIROOT_PORT = 8088;

static char msg_buffer[1000];

void request_lease(int is_controller, const char* hw_addr)
{
    int sock;
    int bytes;

    sock = tcp_active_open(WIROOT_ADDRESS, WIROOT_PORT);
    if(sock == -1) {
        DEBUG_MSG("error connecting to server");
        exit(1);
    }

    struct cchan_request request;
    memset(&request, 0, sizeof(request));
    request.type = is_controller ? CCHAN_CONTROLLER_CONFIG : CCHAN_GATEWAY_CONFIG;
    memcpy(request.hw_addr, hw_addr, ETH_ALEN);

    bytes = send(sock, &request, sizeof(request), 0);
    if(bytes < 0) {
        ERROR_MSG("error sending request");
    }

    char pkt_buff[1500];
    bytes = recv(sock, pkt_buff, sizeof(pkt_buff), 0);
    if(bytes <= 0) {
        ERROR_MSG("error receiving response");
    }

    close(sock);

    struct cchan_response* response = (struct cchan_response*)pkt_buff;

    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &response->priv_ip, p_ip, sizeof(p_ip));

    snprintf(msg_buffer, sizeof(msg_buffer), "Received lease of %s", p_ip);
    DEBUG_MSG(msg_buffer);

    struct cchan_controller_info* cinfo = 
            (struct cchan_controller_info*)(pkt_buff + sizeof(struct cchan_response));

    int i;
    for(i = 0; i < response->controllers; i++) {
        char priv_ip[INET_ADDRSTRLEN];
        char pub_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &cinfo->priv_ip, priv_ip, sizeof(priv_ip));
        inet_ntop(AF_INET, &cinfo->pub_ip, pub_ip, sizeof(pub_ip));

        snprintf(msg_buffer, sizeof(msg_buffer), "Controller %d: %s / %s", i, priv_ip, pub_ip);
        DEBUG_MSG(msg_buffer);

        cinfo++;
    }
}


int main(int argc, char* argv[])
{
    int is_controller = 0;
    char hw_addr[ETH_ALEN];
    int i;

    memset(hw_addr, 0, sizeof(hw_addr));

    const char* opt_string = "gcm:h";

    int opt = getopt(argc, argv, opt_string);
    while(opt != -1) {
        switch(opt) {
            case 'g':
                is_controller = 0;
                break;
            case 'c':
                is_controller = 1;
                break;
            case 'm':
                for(i = 0; i < ETH_ALEN; i++) {
                    hw_addr[i] = atoi(optarg);
                }
                break;
            case 'h':
            default:
                printf("Usage: %s [-g|-c] [-m mac]\n", argv[0]);
                exit(1);
                break;
        }

        opt = getopt(argc, argv, opt_string);
    }

    DEBUG_MSG("Beginning lease request.");
    request_lease(is_controller, hw_addr);

    return 0;
}

