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

//int sendPacket(char *packet, int size, struct interface *ife, struct sockaddr_in *dst, uint32_t *pseq_num)
//{
//    int rtn = 0;
//    if ( ife == NULL )
//    {
//        ERROR_MSG("Tried to send packet over null interface");
//        return FAILURE;
//    }
//    // Getting a sequence number should be done as close to sending as possible
//    struct tunhdr tun_hdr;
//    memset(&tun_hdr, 0, sizeof(tun_hdr));
//
//    //if(*pseq_num == -1) {
//    //    *pseq_num = getSeqNo();
//   // }
//
//    tun_hdr.seq = 0;//htonl(*pseq_num);
//    //tun_hdr.client_id = 0; // TODO: Add a client ID.
//    //tun_hdr.node_id = htons(getNodeID());
//    //tun_hdr.link_id = htons(ife->id);
//    //tun_hdr.local_seq_no = htons(ife->local_seq_no_out++);
//
//    //fillTunnelTimestamps(&tun_hdr, ife);
//
//    //memcpy(packet, &pktSeqNo, sizeof(pktSeqNo));
//    char *new_packet = (char *)malloc(size + sizeof(struct tunhdr) - TUNTAP_OFFSET);
//    memcpy(new_packet, &tun_hdr, sizeof(struct tunhdr));
//    memcpy(&new_packet[sizeof(struct tunhdr)], &packet[TUNTAP_OFFSET], (size-TUNTAP_OFFSET));
//    int new_size = (size-TUNTAP_OFFSET) + sizeof(struct tunhdr);
//
//    if( (rtn = sendto(ife->sockfd, new_packet, new_size, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr))) < 0)
//    {
//        ERROR_MSG("sendto failed (%d), fd %d, interface: %s, dst: %s, new_size: %d", rtn, ife->sockfd, ife->name, inet_ntoa(dst->sin_addr), new_size);
//
//        return FAILURE;
//    }
//    else
//    {
//        //TODO: Packet sent stats update
//        /*struct timeval now;
//        gettimeofday(&now, 0); 
//
//
//        double que_delay = ife->que_delay - ((now.tv_sec - ife->last_sent.tv_sec)*1000 +  (now.tv_usec - ife->last_sent.tv_usec)/1000) ;
//
//        if (que_delay < 0 ) que_delay = 0;
//
//        que_delay = que_delay + (rtn*8/(ife->avg_active_bw_up))/1000 ;
//
//        ife->que_delay = que_delay;
//
//        gettimeofday(&ife->last_sent,0);*/
//    }
//    free(new_packet);
//    return SUCCESS;
//}
int sendPacket(char *packet, int size, uint16_t node_id, struct interface *src_ife, struct interface *dst_ife, uint32_t *pseq_num)
{
    int rtn = 0;
    if ( src_ife->sockfd == 0 )
    {
        DEBUG_MSG("Tried to send packet over null interface");
        return FAILURE;
    }

    struct sockaddr_in *dst = (struct sockaddr_in*) malloc (sizeof(struct sockaddr_in));
    if(dst == NULL){
        DEBUG_MSG("Couldn't malloc destination address when sending packet");
        return FAILURE;
    }
    memset(dst, 0, sizeof(struct sockaddr_in));
    dst->sin_family = AF_INET;
    dst->sin_port   = dst_ife->data_port;//htons((unsigned short)cont_port);
    dst->sin_addr.s_addr = dst_ife->public_ip.s_addr;

    // Getting a sequence number should be done as close to sending as possible
    struct tunhdr tun_hdr;
    memset(&tun_hdr, 0, sizeof(tun_hdr));

    /*if(*pseq_num == -1) {
        *pseq_num = getSeqNo();
    }*/
    tun_hdr.flags = TUNFLAG_DATA;
    tun_hdr.seq = 0;//htonl(*pseq_num);
    //tun_hdr.client_id = 0; // TODO: Add a client ID.
    tun_hdr.node_id = htons(node_id);
    tun_hdr.link_id = htons(src_ife->index);
    //tun_hdr.local_seq_no = htons(src_ife->local_seq_no_out++);

    //fillTunnelTimestamps(&tun_hdr, src_ife);

    //memcpy(packet, &pktSeqNo, sizeof(pktSeqNo));
    char *new_packet = (char *)malloc(size + sizeof(struct tunhdr) - TUNTAP_OFFSET);
    memcpy(new_packet, &tun_hdr, sizeof(struct tunhdr));
    memcpy(&new_packet[sizeof(struct tunhdr)], &packet[TUNTAP_OFFSET], (size-TUNTAP_OFFSET));
    int new_size = (size-TUNTAP_OFFSET) + sizeof(struct tunhdr);
    if( (rtn = sendto(src_ife->sockfd, new_packet, new_size, 0, (struct sockaddr *)dst, sizeof(struct sockaddr))) < 0)
    {
        ERROR_MSG("sendto failed (%d), fd %d,  dst: %s, new_size: %d", rtn, src_ife->sockfd, inet_ntoa(dst->sin_addr), new_size);

        return FAILURE;
    }
    free(new_packet);
    return SUCCESS;
}