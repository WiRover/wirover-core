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
#include "constants.h"
#include "debug.h"
#include "interface.h"
#include "packet.h"
#include "rootchan.h"
#include "timing.h"
#include "tunnel.h"
#include "util.h"

static struct tunnel *tun = NULL;

/*
 * G E T  T U N N E L 
 */
struct tunnel *getTunnel()
{
    return tun;
}

int tunnel_update(struct tunnel *tun, uint32_t ip, uint32_t netmask, unsigned mtu)
{
    struct sockaddr_in *addr = NULL;
    struct ifreq ifr;
    int ret = FAILURE;
    int sock = -1;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sock < 0) {
        ERROR_MSG("socket failed");
        goto finish;
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, tun->name, sizeof(ifr.ifr_name));
    ifr.ifr_mtu = mtu;
    
    if(ioctl(sock, SIOCSIFMTU, &ifr) < 0)
    {
        ERROR_MSG("ioctl(SIOCSIFADDR) set MTU failed");
        goto finish;
    }

    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = ip;

    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    if(ioctl(sock, SIOCSIFADDR, &ifr) < 0)
    {
        ERROR_MSG("ioctl(SIOCSIFADDR) set IP failed");
        goto finish;
    }

    ifr.ifr_netmask.sa_family = AF_INET;
    struct in_addr *netmask_dst = &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
    netmask_dst->s_addr = netmask;
    if(ioctl(sock, SIOCSIFNETMASK, &ifr) < 0)
    {
        ERROR_MSG("ioctl(SIOCSIFNETMASK) set netmask failed");
        goto finish;
    }

    ifr.ifr_flags |= IFF_UP;
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ);
    if(ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
    {
        ERROR_MSG("ioctl(SIOCSIFFLAGS) set flags failed");
        goto finish;
    }
    tun->n_private_ip   = ip;
    tun->n_netmask      = netmask;
    ret = SUCCESS;

finish:
    if(sock > 0)
    {
        close(sock);
    }
    return ret;
}

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
static int tunnelAlloc(struct tunnel *tun, int mtu)
{
    struct ifreq ifr;

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

    return fd;

failure:
    if(fd >= 0)
    {
        close(fd);
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

    tun->remotePort     = get_data_port();
    tun->localPort      = get_data_port();
    //TODO: Fill this in from root server
    tun->controlPort    = 0;

    tun->destAddr.sin_family        = 0;
    tun->destAddr.sin_port          = 0;  
    tun->destAddr.sin_addr.s_addr   = 0;

    //tun = (struct tunnel *)malloc(sizeof(struct tunnel));

    if((tun->tunnelfd = tunnelAlloc(tun, mtu)) < 0)
    {
        ERROR_MSG("tunnelAlloc failed");
        return FAILURE;
    }

    tunnel_update(tun, ip, netmask, mtu);

    if ( ioctl(tun->tunnelfd, TUNSETNOCSUM, 1) < 0 )
    {
        ERROR_MSG("ioctl(TUNSETNOCSUM) failed");
        return FAILURE;
    }

    if(add_route(ip, 0, netmask, 0, tun->name) < 0)
    {
        ERROR_MSG("Could not add route for tunnel traffic");
        return FAILURE;
    }
    return SUCCESS;
} // End function tunnelCreate()

void add_tunnel_header(uint8_t type, struct packet *pkt, 
    struct interface *src_ife, struct interface *update_ife, uint32_t global_seq, uint32_t *remote_ts)
{
    // Getting a sequence number should be done as close to sending as possible
    struct tunhdr tun_hdr;
    memset(&tun_hdr, 0, sizeof(struct tunhdr));

    tun_hdr.type = type;
    tun_hdr.version = get_tunnel_version();
    tun_hdr.node_id = htons(get_unique_id());
    tun_hdr.link_id = htons(src_ife->index);
    tun_hdr.global_seq = htonl(global_seq);

    if(update_ife != NULL){
        tun_hdr.link_seq = htonl(update_ife->local_seq++);
        tun_hdr.path_ack = htonl(update_ife->remote_seq);

        struct timeval tv;
        get_monotonic_time(&tv);
        tun_hdr.local_ts = htonl(tv.tv_sec * USECS_PER_SEC + tv.tv_usec);
    }

    if(remote_ts != NULL)
        tun_hdr.remote_ts = htonl(*remote_ts);
    packet_push(pkt, sizeof(struct tunhdr));
    *(struct tunhdr *)pkt->data = tun_hdr;
}
