#include <linux/ip.h>

void compute_ip_checksum(struct iphdr *ip_hdr);
void compute_tcp_checksum(char *tcp_hdr_body, int length, __be32 src, __be32 dst);