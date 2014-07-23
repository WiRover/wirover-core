#include <arpa/inet.h>

#include "interface.h"
#include "debug.h"
#include "sockets.h"
#include "tunnel.h"
#include "select_interface.h"

int sendPacket(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife)
{
    if(dst_ife == NULL || src_ife == NULL)
    {
        DEBUG_MSG("Tried to send packet to null interface");
        return FAILURE;
    }
    struct sockaddr_storage dst;
    build_data_sockaddr(dst_ife, &dst);
    return send_sock_packet(flags, packet, size, node_id, src_ife, &dst);
}

int send_sock_packet(uint8_t flags, char *packet, int size, uint16_t node_id, struct interface *src_ife, struct sockaddr_storage *dst)
{
    int sockfd = src_ife->sockfd;
    int rtn = 0;
    if ( sockfd == 0 )
    {
        DEBUG_MSG("Tried to send packet over bad sockfd for interface %d", src_ife->name);
        return FAILURE;
    }
    char *new_packet = (char *)malloc(size + sizeof(struct tunhdr));
    int new_size = add_tunnel_header(flags, packet, size, new_packet, node_id, src_ife);

    if( (rtn = sendto(sockfd, new_packet, new_size, 0, (struct sockaddr *)dst, sizeof(struct sockaddr))) < 0)
    {
        ERROR_MSG("sendto failed (%d), fd %d,  dst: %s, new_size: %d", rtn, sockfd, inet_ntoa(((struct sockaddr_in*)dst)->sin_addr), new_size);

        return FAILURE;
    }
    src_ife->packets_since_ack++;
    if(src_ife->packets_since_ack > 5) { src_ife->st_state = ST_STALLED; }
    free(new_packet);
    return SUCCESS;
}