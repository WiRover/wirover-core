#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include "configuration.h"
#include "debug.h"
#include "flowTable.h"
#include "interface.h"
#include "policyTable.h"
#include "packetBuffer.h"
#include "netlink.h"
#include "rwlock.h"
#include "selectInterface.h"
#include "sockets.h"
#include "tunnelInterface.h"

#ifndef SIOCGSTAMP
# define SIOCGSTAMP 0x8906
#endif


static struct buffer_storage *packet_buffer[PACKET_BUFFER_SIZE];

int handleInboundPacket(int tunfd, int data_socket);
int handleOutboundPacket(int tunfd, struct tunnel *tun);
int handleNoControllerPacket(int tunfd, fd_set readSet);
int handlePackets();

static int                  running = 0;
static pthread_t            data_thread;
static int                  data_socket = -1;
static struct sockaddr_in   *cont_addr;
struct tunnel *tun;

int start_data_thread(struct tunnel *tun_in, uint32_t cont_ip, uint16_t cont_port)
{
    tun = tun_in;
    cont_addr = (struct sockaddr_in*) malloc (sizeof(struct sockaddr_in));
    memset(cont_addr, 0, sizeof(cont_addr));
    cont_addr->sin_family = AF_INET;
    cont_addr->sin_port   = htons((unsigned short)cont_port);
    cont_addr->sin_addr.s_addr = cont_ip;
    if(running) {
        DEBUG_MSG("Data thread already running");
        return 0;
    }

    data_socket = udp_bind_open(get_data_port(), 0);
    if(data_socket == FAILURE) {
        DEBUG_MSG("Data thread cannot start due to failure");
        return FAILURE;
    }

    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result = pthread_create(&data_thread, &attr, handlePackets, 0);
    if(result != 0) {
        ERROR_MSG("Creating thread failed");
        close(data_socket);
        data_socket = -1;
        return FAILURE;
    }

    running = 1;

    pthread_attr_destroy(&attr);
    return 0;
}

int handlePackets()
{
    // The File Descriptor set to add sockets to
    fd_set read_set;
    sigset_t orig_set;

    initPacketBuffer(packet_buffer);


    while( 1 )
    {
        FD_ZERO(&read_set);
        FD_SET(data_socket, &read_set);
        FD_SET(tun->tunnelfd, &read_set);
        
	    obtain_read_lock(&interface_list_lock);
	    struct interface* curr_ife = interface_list;
        while (curr_ife) {
            DEBUG_MSG("Sockfd: %d",curr_ife->sockfd);
            if(curr_ife->sockfd > 0){
                FD_SET(curr_ife->sockfd, &read_set);
            }
            curr_ife = curr_ife->next;
        }
	    release_read_lock(&interface_list_lock);
        // Pselect should return
        // when SIGINT, or SIGTERM is delivered, but block SIGALRM
        sigemptyset(&orig_set);
        sigaddset(&orig_set, SIGALRM);
        
        int rtn = pselect(FD_SETSIZE, &read_set, NULL, NULL, NULL, &orig_set);
        // Make sure select didn't fail
        if( rtn < 0 && errno == EINTR) 
        {
            DEBUG_MSG("select() failed");
            continue;
        }

        if( FD_ISSET(data_socket, &read_set) ) 
        {
            handleInboundPacket(tun->tunnelfd, data_socket);
        }

        obtain_read_lock(&interface_list_lock);
	    curr_ife = interface_list;
        while (curr_ife) {
            if( FD_ISSET(curr_ife->sockfd, &read_set) ) 
            {
                handleInboundPacket(tun->tunnelfd, curr_ife->sockfd);
            }
            curr_ife = curr_ife->next;
        }
	    release_read_lock(&interface_list_lock);

        if( FD_ISSET(tun->tunnelfd, &read_set) ) 
        {
            handleOutboundPacket(tun->tunnelfd, tun);
        }

    } // while( 1 )

    return SUCCESS;
} // End function int handlePackets()

int handleInboundPacket(int tunfd, int data_socket) 
{
    struct  tunhdr n_tun_hdr;
    int     bufSize;
    char    buffer[get_mtu()];

    struct sockaddr_storage     from;
    unsigned    fromlen = sizeof(from);

    bufSize = recvfrom(data_socket, buffer, sizeof(buffer), 0, 
        (struct sockaddr *)&from, &fromlen);
    if(bufSize < 0) {
        ERROR_MSG("recvfrom() failed");
        return FAILURE;
    }

    struct timeval arrival_time;
    if(ioctl(data_socket, SIOCGSTAMP, &arrival_time) == -1) {
        ERROR_MSG("ioctl SIOCGSTAMP failed");
        gettimeofday(&arrival_time, 0);
    }

    // Get the tunhdr (should be the first n bytes in the packet)
    // store network format in temporary struct
    memcpy(&n_tun_hdr, buffer, sizeof(struct tunhdr));

    // Copy temporary to host format
    unsigned int h_seq_no = ntohl(n_tun_hdr.seq);

    if(addSeqNum(packet_buffer, h_seq_no) == NOT_ADDED) {
        return SUCCESS;
    }

    // This is needed to notify tun0 we are passing an IP packet
    // Have to pass in the IP proto as last two bytes in ethernet header
    //
    // Copy in four bytes, these four bytes represent the four bytes of the
    // tunnel header (added by the tun device) this field is in network order.
    // In host order it would be 0x00000800 the first two bytes (0000) are
    // the flags field, the next two byte (0800 are the protocol field, in this
    // case IP): http://www.mjmwired.net/kernel/Documentation/networking/tuntap.txt

    const struct iphdr *ip_hdr = (const struct iphdr *)(buffer + sizeof(struct tunhdr));
    unsigned short tun_info[2];
    tun_info[0] = 0; //flags
    tun_info[1] = ip_hdr->version == 6 ? htons(ETH_P_IPV6) : htons(ETH_P_IP);

    memcpy(&buffer[sizeof(struct tunhdr) - TUNTAP_OFFSET], tun_info, TUNTAP_OFFSET);


    DEBUG_MSG("Writing data");
    if( write(tunfd, buffer, 
        (bufSize)) < 0) 
    /*if( write(tunfd, &buffer[sizeof(struct tunhdr)-TUNTAP_OFFSET], 
        (bufSize-sizeof(struct tunhdr)+TUNTAP_OFFSET)) < 0) */
    {
        ERROR_MSG("write() failed");
        return FAILURE;
    }


    return SUCCESS;
} // End function int handleInboundPacket()

int handleOutboundPacket(int tunfd, struct tunnel * tun) 
{
    int bufSize;
    char buffer[get_mtu()];

    if( (bufSize = read(tunfd, buffer, get_mtu())) < 0) 
    {
        ERROR_MSG("read packet failed");
    } 
    else 
    {

        struct flow_tuple *ft = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
        struct iphdr    *ip_hdr = (struct iphdr *)(buffer + TUNTAP_OFFSET);
        struct tcphdr   *tcp_hdr = (struct tcphdr *)(buffer + TUNTAP_OFFSET + (ip_hdr->ihl * 4));

        // Policy and Flow table
        fill_flow_tuple(ip_hdr, tcp_hdr, ft);

        struct flow_entry *ftd = get_flow_entry(ft);
        if(ftd == NULL) {
            struct policy_entry *pd = malloc(sizeof(struct policy_entry));
            getMatch(ft, pd, EGRESS);
            update_flow_table(ft,pd->action, pd->type, pd->alg_name);
            free(pd);
            ftd = get_flow_entry(ft);
        }

        free(ft);

        // Check for drop
        if((ftd->action & POLICY_ACT_DROP) != 0) {
            return SUCCESS;
        }

        // Send on all interfaces
        if((ftd->action & POLICY_OP_DUPLICATE) != 0) {
            //sendAllInterfaces(buffer, bufSize);
            return SUCCESS;
        }

        // Select interface and send
        int rtn = 0;
#ifdef CONTROLLER
#endif
#ifdef GATEWAY
        struct interface *ife;
        obtain_read_lock(&interface_list_lock);

        ife = interface_list;
        sendPacket(buffer, bufSize, ife, cont_addr, 0);
        release_read_lock(&interface_list_lock);
#endif

        //ife = selectInterface(algo, port, size - offset, packet + offset);

        /*if(strcmp(ftd->alg_name, "rr_conn") == 0) {
        rtn = stripePacket(buffer, bufSize, RR_CONN);
        }
        else if(strcmp(ftd->alg_name, "rr_pkt") == 0) {
        rtn = stripePacket(buffer, bufSize, RR_PKT);
        }
        else if(strcmp(ftd->alg_name, "wrr_conn") == 0) {
        rtn = stripePacket(buffer, bufSize, WRR_CONN);
        }
        else if(strcmp(ftd->alg_name, "wrr_pkt") == 0) {
        rtn = stripePacket(buffer, bufSize, WRR_PKT);
        }
        else if(strcmp(ftd->alg_name, "wrr_pktv1") == 0) {
        rtn = stripePacket(buffer, bufSize, WRR_PKT_v1);
        }
        else if(strcmp(ftd->alg_name, "wdrr_pkt") == 0) {
        rtn = stripePacket(buffer, bufSize, WDRR_PKT);
        }
        else if(strcmp(ftd->alg_name, "spf") == 0) {
        rtn = stripePacket(buffer, bufSize, SPF);
        }
        else*/ {
            //rtn = stripePacket(buffer, bufSize, getRoutingAlgorithm());
        }

        if(rtn < 0) {
            ERROR_MSG("stripePacket() failed");
        }
    }

    return SUCCESS;
} // End function int handleOutboundPacket()