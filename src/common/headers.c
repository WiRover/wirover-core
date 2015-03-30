#include <linux/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "debug.h"
#include "headers.h"
struct psuedo_ip_hdr {
    __be32 src;
    __be32 dst;
    __u8  zeroes;
    __u8  protocol;
    __be16 length;
};
/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

void compute_ip_checksum(struct iphdr* iphdrp){
    iphdrp->check = 0;
    iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}

void compute_transport_checksum(struct packet *pkt)
{
    struct iphdr * ip_hdr = ((struct iphdr*)pkt->data);
    int proto = ip_hdr->protocol;
    uint32_t dst_ip = ip_hdr->daddr;

    if(proto == 6) {
        packet_pull(pkt, sizeof(struct iphdr));
        compute_tcp_checksum(pkt->data, pkt->data_size, ip_hdr->saddr, dst_ip);
        packet_push(pkt, sizeof(struct iphdr));

    }
    else if(proto == 17) {
        packet_pull(pkt, sizeof(struct iphdr));
        compute_udp_checksum(pkt->data, pkt->data_size, ip_hdr->saddr, dst_ip);
        packet_push(pkt, sizeof(struct iphdr));
    }
}

void compute_tcp_checksum(char *tcp_hdr_body, int length, __be32 src, __be32 dst) {
    char buffer[sizeof(struct psuedo_ip_hdr) + length];
    memset(buffer, 0, sizeof(buffer));
    struct psuedo_ip_hdr *psuedo_hdr = (struct psuedo_ip_hdr *)buffer;
    struct tcphdr *fake_tcp_hdr = (struct tcphdr *)&buffer[sizeof(struct psuedo_ip_hdr)];
    memcpy(fake_tcp_hdr, tcp_hdr_body, length);

    psuedo_hdr->src = src;
    psuedo_hdr->dst = dst;
    psuedo_hdr->protocol = 6;
    psuedo_hdr->length = htons(length);
    fake_tcp_hdr->check = 0;

    ((struct tcphdr *)tcp_hdr_body)->check = compute_checksum((unsigned short*)buffer, sizeof(buffer));
}

void compute_udp_checksum(char *udp_hdr_body, int length, __be32 src, __be32 dst) {
    char buffer[sizeof(struct psuedo_ip_hdr) + length];
    memset(buffer, 0, sizeof(buffer));
    struct psuedo_ip_hdr *psuedo_hdr = (struct psuedo_ip_hdr *)buffer;
    struct udphdr *fake_udp_hdr = (struct udphdr *)&buffer[sizeof(struct psuedo_ip_hdr)];
    memcpy(fake_udp_hdr, udp_hdr_body, length);

    psuedo_hdr->src = src;
    psuedo_hdr->dst = dst;
    psuedo_hdr->protocol = 17;
    psuedo_hdr->length = htons(length);
    fake_udp_hdr->check = 0;

    ((struct udphdr *)udp_hdr_body)->check = compute_checksum((unsigned short*)buffer, sizeof(buffer));
}