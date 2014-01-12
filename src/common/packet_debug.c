/*
 * P A C K E T  D E B U G . C
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "packet_debug.h"
#include "parameters.h"
#include "interface.h"
#include "utils.h"

static char log_buf[MAX_LINE];

void hex_to_ipstr(char *ip_addr, int addr)
{
        int oct1, oct2, oct3, oct4;

        oct1 =  (int)((0xff000000 & addr)>>24);
        oct2 =  (int)((0x00ff0000 & addr)>>16);
        oct3 =  (int)((0x0000ff00 & addr)>>8);
        oct4 =  (int)(0x000000ff & addr);
        sprintf(ip_addr, "%d.%d.%d.%d", oct1, oct2, oct3, oct4);

}

void print_ethhdr(struct ethhdr *eth_hdr, FILE *file)
{
    sprintf(log_buf, "Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
        eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
	write_log(log_buf);

    sprintf(log_buf, "Dest MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
        eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2], eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
	write_log(log_buf);

	sprintf(log_buf, "Type field: 0x%04x\n\n", eth_hdr->h_proto);
	write_log(log_buf);
}

void print_iphdr(struct iphdr *ip_header, FILE *file)
{
	char ipstr[20];

	sprintf(log_buf, "                                    1                               3 \n");
	write_log(log_buf);
	sprintf(log_buf, " 0        4        8                6                               1 \n");
	write_log(log_buf);
	sprintf(log_buf, "IP HEADER\n");
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| version|  IHL   |Type of service |          Total Length           |\n");
	write_log(log_buf);
	sprintf(log_buf, "|  %04d  |  %04d  |    %08d    |       0x%016x        |\n", ip_header->version, ip_header->ihl, ip_header->tos, ntohs(ip_header->tot_len));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Identification                   |flags/  Fragment Offset          |\n");
	write_log(log_buf);
	sprintf(log_buf, "|       0x%016x         |       0x%016x        |\n", ntohs(ip_header->id), ntohs(ip_header->frag_off));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Time to Live   | Protocol       | Header Checksum                  |\n");
	write_log(log_buf);
	sprintf(log_buf, "|    %08d    |    %08d    |        0x%016x        |\n", ip_header->ttl, ip_header->protocol, ntohs(ip_header->check));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Source Address                                                     |\n");
	write_log(log_buf);
	sprintf(log_buf, "|                 0x%032x                 |\n", ntohl(ip_header->saddr));
	write_log(log_buf);
	hex_to_ipstr(ipstr, ntohl(ip_header->saddr));
	sprintf(log_buf, "| %s |\n", ipstr);
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Destination Address                                                |\n");
	write_log(log_buf);
	sprintf(log_buf, "|                 0x%032x                 |\n", ntohl(ip_header->daddr));
	write_log(log_buf);
	hex_to_ipstr(ipstr, ntohl(ip_header->daddr));
	sprintf(log_buf, "| %s |\n", ipstr);
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Options                                                            |\n");
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "\n");
	write_log(log_buf);
}

void print_tcphdr(unsigned char *header, FILE *file)
{
	struct tcphdr *tcp_header = (struct tcphdr *)header;

	sprintf(log_buf, "TCP HEADER\n");	
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Source Port                    | Destination Port                  |\n");
	write_log(log_buf);
	sprintf(log_buf, "|       0x%016x       |        0x%016x         |\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
	write_log(log_buf);
	sprintf(log_buf, "|        %016d        |         %016d          |\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Sequence Number                                                    |\n");
	write_log(log_buf);
	sprintf(log_buf, "|                 0x%032x                 |\n", ntohl(tcp_header->seq));
	write_log(log_buf);
	sprintf(log_buf, "| %d |\n", ntohl(tcp_header->seq));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Acknowledgement Number                                             |\n");
	write_log(log_buf);
	sprintf(log_buf, "|                 0x%032x                 |\n", ntohl(tcp_header->ack_seq));
	write_log(log_buf);
	sprintf(log_buf, "| %d |\n", ntohl(tcp_header->ack_seq));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Offset |Reserved| Flags          | Window                          |\n");
	write_log(log_buf);
	sprintf(log_buf, "|  xxx   |  xxx   |     xxx        |       0x%016x        |\n", ntohs(tcp_header->window));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Checksum                         | Urgent Pointer                  |\n");
	write_log(log_buf);
	sprintf(log_buf, "|        0x%016x        |        0x%016x       |\n", ntohs(tcp_header->check), ntohs(tcp_header->urg_ptr));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);

}

void print_udphdr(struct udphdr *udp_header, FILE *file)
{
	sprintf(log_buf, "UDP HEADER\n");
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Source Port                    | Destinations Port                 |\n");
	write_log(log_buf);
	sprintf(log_buf, "|       0x%016x       |        0x%016x         |\n", ntohs(udp_header->source), ntohs(udp_header->dest));
	write_log(log_buf);
	sprintf(log_buf, "|        %016d        |         %016d          |\n", ntohs(udp_header->source), ntohs(udp_header->dest));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
	sprintf(log_buf, "| Length                         | Checksum                          |\n");
	write_log(log_buf);
	sprintf(log_buf, "|       0x%016x       |        0x%016x         |\n", ntohs(udp_header->len), ntohs(udp_header->check));
	write_log(log_buf);
	sprintf(log_buf, "|        %016d        |         %016d          |\n", ntohs(udp_header->len), ntohs(udp_header->check));
	write_log(log_buf);
	sprintf(log_buf, "----------------------------------------------------------------------\n");
	write_log(log_buf);
}


void print_pkthdr(unsigned char *pkthdr, FILE *file)
{
	struct ethhdr *ethernet_header = (struct ethhdr *)pkthdr;
	print_ethhdr(ethernet_header, file);
	if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
	{
		struct iphdr *ip_header = (struct iphdr *)(pkthdr + sizeof(struct ethhdr));
        	print_iphdr(ip_header, file);
		if(ip_header->protocol == IPPROTO_TCP)
		{
			struct tcphdr *tcp_header = (struct tcphdr *)(pkthdr + sizeof(struct ethhdr) + ip_header->ihl*4);
            		print_tcphdr((unsigned char *)tcp_header, file);
		}
		else if(ip_header->protocol == IPPROTO_UDP)
		{
			struct udphdr *udp_header = (struct udphdr *)(pkthdr + sizeof(struct ethhdr) + ip_header->ihl*4);
            		print_udphdr(udp_header, file);
		}
	}
}


void print_encappkt(unsigned char *pkthdr, FILE *file)
{
    int offset = sizeof(struct ethhdr);

    struct iphdr *ip_header = (struct iphdr *)(pkthdr + offset);
    offset += ip_header->ihl*4;

    print_iphdr(ip_header, file);
    if(ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)(pkthdr + offset);
        print_tcphdr((unsigned char *)tcp_header, file);
    }
    else if(ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)(pkthdr + offset);
        print_udphdr(udp_header, file);
    }

}

