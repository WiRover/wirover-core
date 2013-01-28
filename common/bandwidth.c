#include <arpa/inet.h>
#include <sys/socket.h>

#include "bandwidth.h"
#include "config.h"
#include "configuration.h"
#include "debug.h"
#include "rootchan.h"

/*
 * Send a burst of UDP packets to the given destination.
 *
 * Returns -1 if an error occurred at any point; otherwise, returns the number
 * of bytes sent.
 *
 * TODO: Make the number of number of packets and packet length configurable on
 * a per-interface basis.  Depending on the capacity of the interfaces, some will
 * require more or fewer bytes to test.  Ten packets takes a long time on a slow
 * 3G uplink but may be insignificant on WiFi or wired, for example.
 */
int send_udp_burst(int sockfd, char *buffer, unsigned length, 
        struct sockaddr *dest, socklen_t dest_len, 
        unsigned short link_id, double bandwidth, unsigned timeout)
{
    const unsigned num_packets = BW_UDP_PKTS;
    const unsigned packet_len = length < get_mtu() ? length : get_mtu();
    unsigned bytes_sent = 0;

    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;
    bw_hdr->type = BW_TYPE_BURST;
    bw_hdr->size = htonl(packet_len);
    bw_hdr->timeout = htonl(timeout);
    bw_hdr->bandwidth = bandwidth;
    bw_hdr->node_id = htons(get_unique_id());
    bw_hdr->link_id = htons(link_id);
    bw_hdr->remaining = htons(num_packets);

    // The first packet is small, just the header, and indicates to the
    // receiver the start time and length of the burst.
    int result = sendto(sockfd, buffer, sizeof(struct bw_hdr), 0, dest, dest_len);
    if(result < 0) {
        ERROR_MSG("sendto failed");
        return -1;
    } else {
        bytes_sent += result;
    }

    int i;
    for(i = 0; i < num_packets; i++) {
        bw_hdr->remaining = htons(num_packets - i - 1);

        int result = sendto(sockfd, buffer, packet_len, 0, dest, dest_len);
        if(result < 0) {
            ERROR_MSG("sendto failed");
            return -1;
        } else {
            bytes_sent += result;
        }
    }

    return bytes_sent;
}

