#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "contchan.h"
#include "debug.h"
#include "sockets.h"

const char* WIROOT_ADDRESS = "127.0.0.1";
const unsigned short WIROOT_PORT = 8082;

int mac = 0;

void request_lease()
{
    int sock;
    int bytes;

    sock = tcp_active_open(WIROOT_ADDRESS, WIROOT_PORT);
    if(sock == -1) {
        DEBUG_MSG("error connecting to server");
        exit(1);
    }

    struct contchan_lease_request request;
    memset(&request, 0, sizeof(request));
    request.type = CONTCHAN_LEASE_REQUEST;
    *(int*)request.hw_addr = mac++;

    bytes = send(sock, &request, sizeof(request), 0);
    if(bytes < 0) {
        ERROR_MSG("error sending request");
    }
    shutdown(sock, SHUT_WR);

    struct contchan_lease_response response;
    bytes = recv(sock, &response, sizeof(response), 0);
    if(bytes < sizeof(response)) {
        ERROR_MSG("error receiving response");
    }

    close(sock);
}


int main(int argc, char* argv[])
{
    int i;
    for(i = 0; i < 1000; i++) {
        request_lease();
    }

    return 0;
}

