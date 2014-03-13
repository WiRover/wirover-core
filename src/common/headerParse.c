#include "headerParse.h"

int fill_flow_tuple(struct iphdr* ip_hdr, struct tcphdr* tcp_hdr, struct flow_tuple* ft) {
    memset(ft, 0, sizeof(struct flow_tuple));
    ft->net_proto = ip_hdr->version;
    ft->dAddr = ip_hdr->daddr;
    ft->sAddr = ip_hdr->saddr;
    ft->proto = ip_hdr->protocol;
    ft->dPort = tcp_hdr->dest;
    ft->sPort = tcp_hdr->source;

    return 0;
}
