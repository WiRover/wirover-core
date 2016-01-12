#include <netinet/ip_icmp.h>
#include <stdio.h>

#include "debug.h"
#include "headers.h"
#include "interface.h"
#include "icmp_ping.h"
#include "state.h"


int send_icmp_ping(struct interface *ife)
{
    struct packet *pkt = alloc_packet(sizeof(struct icmphdr), 0);
    packet_push(pkt, sizeof(struct icmphdr));
    struct icmphdr *ping = (struct icmphdr *)pkt->data;
    ping->type = ICMP_ECHO;
    ping->code = 0;
    ping->checksum = 0;
    ping->un.echo.id = htons(ife->index);
    ping->un.echo.sequence = htons(ife->next_icmp_seq_no++);
    ping->checksum = compute_checksum((short unsigned int *)pkt->data, pkt->data_size);

    int ret;
    if(sendto(ife->icmp_sockfd, pkt->data, pkt->data_size, 0, (struct sockaddr *)icmp_ping_dest, sizeof(struct sockaddr)) < 0) {
        ERROR_MSG("ICMP ping failure");
        ret = FAILURE;
    }
    else {
        ret = SUCCESS;
    }

    free_packet(pkt);
    return ret;
}

int handle_incoming_icmp_ping(struct interface *ife, struct packet *pkt)
{
    if(!(state & GATEWAY_CONTROLLER_AVAILABLE)) {
        ife->state = ACTIVE;
    }
    free_packet(pkt);
    return SUCCESS;
}