#include <arpa/inet.h>
#include <sys/socket.h>

#include "bandwidth.h"
#include "config.h"
#include "configuration.h"
#include "debug.h"
#include "rootchan.h"
#include "sockets.h"

int session_send(const struct bw_session *session, int sockfd, int type)
{
    const unsigned num_packets = BW_UDP_PKTS;
    const unsigned packet_len = session->mtu;

    int bytes_sent = 0;

    char *buffer = malloc(packet_len);
    if(!buffer) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    struct bw_hdr *bw_hdr = (struct bw_hdr *)buffer;
    bw_hdr->type = type;
    bw_hdr->mtu = htonl(packet_len);
    bw_hdr->timeout = htonl(session->local_timeout);
    bw_hdr->bandwidth = session->measured_bw;
    bw_hdr->node_id = htons(session->key.node_id);
    bw_hdr->link_id = htons(session->key.link_id);
    bw_hdr->session_id = htons(session->key.session_id);
    bw_hdr->remaining = htons(num_packets);
    
    int result = sendto(sockfd, buffer, sizeof(struct bw_hdr), 0, 
            (struct sockaddr *)&session->key.addr, session->key.addr_len);
    if(result < 0) {
        char ipstr[39];
        sockaddr_ntop((struct sockaddr *)&session->key.addr, ipstr, sizeof(struct sockaddr));
        ERROR_MSG("sendto failed to %s, sockfd: %d", ipstr, sockfd);
        bytes_sent = -1;
        goto out;
    } else {
        bytes_sent = result;
    }

    if(type == BW_TYPE_BURST) {
        fill_buffer_random(buffer + sizeof(struct bw_hdr), 
                packet_len - sizeof(struct bw_hdr));

        int i;
        for(i = 0; i < num_packets; i++) {
            bw_hdr->remaining = htons(num_packets - i - 1);

            int result = sendto(sockfd, buffer, packet_len, 0,
                (struct sockaddr *)&session->key.addr, session->key.addr_len);
            if(result < 0) {
                ERROR_MSG("sendto failed");
                bytes_sent = -1;
                goto out;
            } else {
                bytes_sent += result;
            }
        }
    }

out:
    free(buffer);
    return bytes_sent;
}

int session_send_rts(const struct bw_session *session, int sockfd)
{
    return session_send(session, sockfd, BW_TYPE_RTS);
}

int session_send_cts(const struct bw_session *session, int sockfd)
{
    return session_send(session, sockfd, BW_TYPE_CTS);
}

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
int session_send_burst(const struct bw_session *session, int sockfd)
{
    return session_send(session, sockfd, BW_TYPE_BURST);
}

int session_send_stats(const struct bw_session *session, int sockfd)
{
    return session_send(session, sockfd, BW_TYPE_STATS);
}


