#include <arpa/inet.h>

#include "interface.h"
#include "debug.h"
#include "sockets.h"
#include "tunnel.h"

struct interface *selectInterface(int algo, unsigned short port, int size, char *packet)
{
    /*struct interface *head = head_link__;

    switch(algo)
    {
    case RR_CONN:
    return per_conn_rr(head, port);

    case RR_PKT:
    return per_packet_rr(head);

    case WRR_CONN:
    return per_conn_wrr(head, packet, size);

    case WRR_PKT:
    return per_packet_wrr(head);

    case WRR_PKT_v1:
    return per_packet_wrr_v1(head);

    case WDRR_PKT:
    return per_packet_wdrr(head, size);

    case SPF:
    return per_packet_spf(head, size);

    default:
    return NULL;
    }

    return NULL;*/
    return NULL;
} // End function int selectInterface()

int sendPacket(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife)
{
    int sockfd = src_ife->sockfd;
    if(dst_ife == NULL)
    {
        DEBUG_MSG("Tried to send packet to null interface");
        return FAILURE;
    }
    struct sockaddr_storage dst;
    build_data_sockaddr(dst_ife, &dst);
    int rtn = 0;
    if ( sockfd == 0 )
    {
        DEBUG_MSG("Tried to send packet over bad sockfd for interface %d", src_ife->index);
        return FAILURE;
    }
    char *new_packet = (char *)malloc(size + sizeof(struct tunhdr));
    int new_size = add_tunnel_header(flags, packet, size, new_packet, node_id, src_ife);

    if( (rtn = sendto(sockfd, new_packet, new_size, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr))) < 0)
    {
        ERROR_MSG("sendto failed (%d), fd %d,  dst: %s, new_size: %d", rtn, sockfd, inet_ntoa(((struct sockaddr_in*)&dst)->sin_addr), new_size);

        return FAILURE;
    }
    free(new_packet);
    return SUCCESS;
}