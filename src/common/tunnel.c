/*
 * T U N N E L  I N T E R F A C E . C
 *
 * This file contains functions that create, initialize and destroy
 * the virtual tunnel interface.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "configuration.h"
#include "debug.h"
#include "interface.h"
#include "tunnel.h"

static struct tunnel *tun = NULL;
    
/*
 * D U M P  T U N  H D R 
 *
 * Returns (void)
 */
void dumpTunHdr(struct tunhdr *tun_hdr)
{
    DEBUG_MSG("TUN_HDR");
    //printf("\tseq_no:       %u\n", ntohl(tun_hdr->seq_no));
    //printf("\tsend_ts:      %u\n", ntohl(tun_hdr->send_ts));
    //printf("\trecv_ts:      %u\n", ntohl(tun_hdr->recv_ts));
    //printf("\tservice:      %u\n", ntohl(tun_hdr->service));
    //printf("\tclient_id:    %u\n", ntohs(tun_hdr->client_id));
    //printf("\tnode_id:      %u\n", ntohs(tun_hdr->node_id));
    //printf("\tlink_id:      %u\n", ntohs(tun_hdr->link_id));
    //printf("\tlocal_seq_no: %u\n\n", ntohs(tun_hdr->local_seq_no));
} // End function void dumpTunHdr()

/*
 * G E T  T U N N E L 
 */
struct tunnel *getTunnel()
{
    return tun;
} // End functionstruct tunnel *getTunnel()


/*
 * T U N N E L  A L L O C
 *
 * Function to allocate the tun device
 *
 * Returns (int):
 *      Success: tun file descriptor
 *      Failure: -1
 *
 */
static int tunnelAlloc(struct tunnel *tun)
{
    struct sockaddr_in *addr = NULL;
    struct ifreq ifr;

    int sock = -1;

    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0) {
        ERROR_MSG("open failed");
        goto failure;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
    *        IFF_TAP    - TAP device  
    *
    *        IFF_NO_PI - Do not provide packet information  
    */ 
    ifr.ifr_flags = IFF_TUN; 

    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);

    int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if(err < 0) {
        ERROR_MSG("ioctl(TUNSETIFF) failed");
        goto failure;
    }

    strncpy(tun->name, ifr.ifr_name, sizeof(ifr.ifr_name));

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sock < 0) {
        ERROR_MSG("socket failed");
        goto failure;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = tun->n_private_ip;
    //addr->sin_addr.s_addr = inet_addr("192.168.1.2");
    //setTunLocalIP(tun->localIP);

    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    if( (err = ioctl(sock, SIOCSIFADDR, &ifr)) < 0) 
    {
        ERROR_MSG("ioctl(SIOCSIFADDR) set IP failed");
        goto failure;
    }

    ifr.ifr_flags |= IFF_UP;
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    if( (err = ioctl(sock, SIOCSIFFLAGS, &ifr)) < 0) 
    {
        ERROR_MSG("ioctl(SIOCSIFFLAGS) set flags failed");
        goto failure;
    }
    
    // Set up SO_DONTROUTE for tunnel socket
    if(setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, tun->name, IFNAMSIZ) < 0)
    {
        ERROR_MSG("setsockopt(SO_DONTROUTE) on tunnel device failed");
        close(sock);
        return FAILURE;
    }

    close(sock);
    return fd;

failure:
    if(fd >= 0)
    {
        close(fd);
    }
    if(sock > 0)
    {
        close(sock);
    }

    return FAILURE;
} // End function int tunnelAlloc()


/*
 * T U N N E L  C L E A N U P
 *
 * Function the cleanup the tunnel on successful exit
 *
 * Returns (void)
 *
 */
void tunnelCleanup()
{
    
    printf("Cleaning up tunnel . . . \n");
    if ( tun->tunnelfd != 0 ) 
    {
        if ( close(tun->tunnelfd) < 0 )
        {
            DEBUG_MSG("close failed");
        }
    }

    if ( tun != NULL ) 
    {
        free(tun);
    }
} // End function void tunnelCleanup(struct tunnel *tun)


/*
 * T U N N E L  C R E A T E
 * 
 * A function to malloc, and initialize a tunnel structure
 *
 */
int tunnel_create(uint32_t ip, uint32_t netmask, unsigned mtu)
{
    if( (tun = (struct tunnel *)malloc(sizeof(struct tunnel))) == NULL )
    {
        ERROR_MSG("malloc failed");
        return FAILURE;
    }
    
    memset(&tun->name, 0, sizeof(tun->name));

    tun->n_private_ip   = ip;
    tun->remotePort     = get_data_port();
    tun->localPort      = get_data_port();
    //TODO: Fill this in from root server
    tun->controlPort    = 0;

    tun->destAddr.sin_family        = 0;
    tun->destAddr.sin_port          = 0;  
    tun->destAddr.sin_addr.s_addr   = 0;

    //tun = (struct tunnel *)malloc(sizeof(struct tunnel));

    if((tun->tunnelfd = tunnelAlloc(tun)) < 0) 
    {
        ERROR_MSG("tunnelAlloc failed");
        return FAILURE;
    }

    if ( ioctl(tun->tunnelfd, TUNSETNOCSUM, 1) < 0 )
    {
        ERROR_MSG("ioctl(TUNSETNOCSUM) failed");
        return FAILURE;
    } 

    return SUCCESS;
} // End function tunnelCreate()
