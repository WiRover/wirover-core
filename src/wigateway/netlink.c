/*
 * N E T  L I N K . C
 */

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <linux/netlink.h>

#include "../common/utils.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/link_priority.h"
#include "../common/tunnelInterface.h"
#include "../common/contChan.h"
#include "../common/special.h"
#include "../common/udp_ping.h"
#include "scan.h"
#include "netlink.h"

// NetLink Socket
static int net_sockfd;

// Netlink thread variables
static pthread_t        netlink_thread;
static pthread_mutex_t  netlink_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * C R E A T E  N E T  L I N K  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int createNetLinkThread()
{
    pthread_attr_t attr;

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if( pthread_create( &netlink_thread, &attr, netLinkThreadFunc, NULL) )
    {
        ERROR_MSG("createNetLinkThread(): pthread_create failed on netLinkThreadFunc");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);

    return SUCCESS;
} // End function createNetLinkThread()


/*
 * D E S T R O Y  N E T  L I N K  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int destroyNetLinkThread()
{
    DEBUG_MSG("Destroying netlink thread . . . ");
    if ( pthread_join(netlink_thread, NULL) != 0 )
    {
        ERROR_MSG("main(): pthread_join(netlink_thread) failed");
        return FAILURE;
    }

    pthread_mutex_destroy(&netlink_mutex);

    return SUCCESS;
} // End function int destroyNetLinkThread()
                                                 

/*
 * N E T L I N K  T H R E A D  F U N C
 *
 * Returns (void)
 *
 */
void *netLinkThreadFunc(void *arg)
{
    int netlink_sockfd = createNetLinkSocket();
    fd_set netlink_set;

	// Let another thread handle these signals
	// We don't want them to interrupt our socket calls
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &sigset, 0);

    if ( getQuitFlag() ) 
    {
        pthread_exit(NULL);
    }

    while ( 1 )
    {
        if ( getQuitFlag() )
        {
            pthread_exit(NULL);
        }

        // Zero out the file descriptor set
        FD_ZERO(&netlink_set);

        // Add the read file descriptor to the set ( for listening with a controller )
        FD_SET(netlink_sockfd, &netlink_set);

        struct timeval ts;
        ts.tv_sec = 3; 
        ts.tv_usec = 0;

        select(FD_SETSIZE, &netlink_set, NULL, NULL, &ts);
        //GENERAL_MSG("pselect() netlink.c returned\n");

        if( FD_ISSET(netlink_sockfd, &netlink_set) ) 
        {
            //printf("netlink_sockfd is set\n");
            if ( handleNetLinkPacket() < 0 ) 
            {
                // If -1 is returned, we couldn't find an interface to send out of
                continue;
            }
        }
    }

    close(netlink_sockfd);
	pthread_exit(NULL);
} // End function void *netLinkThreadFunc()


/*
 * G E T  N E T  L I N K  S O C K E T
 */
int getNetLinkSocket()
{
    return net_sockfd;
} // End function int getNetLinkSocket()


/*
 * C R E A T E  N E T  L I N K  S O C K E T
 *
 * Returns (int)
 *      Success: A netlink sockfd
 *      Failrue: -1
 */
int createNetLinkSocket()
{

    // Create netlink socket
    if((net_sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        ERROR_MSG("create socket failed");
    }

    // Make the nladdr structure to use for the netlink structure
    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid    = 0; // The kernel will assign a unique id
    nladdr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;


    // Bind the netlink net_sockfd 
    if(bind(net_sockfd, (struct sockaddr*)&nladdr, sizeof(nladdr)) < 0)
    {
        ERROR_MSG("bind() failed");
    }

    return net_sockfd;
} // End function int createNetLinkSocket()


/*
 * H A N D L E  N E T  L I N K  P A C K E T
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int handleNetLinkPacket()
{
    int interface_notify = 0;
    struct link *ife = NULL;

    struct nlmsghdr *nh = NULL;
    struct iovec iov;
    struct msghdr msg;

    char buffer[4096];
    iov.iov_base = buffer;
    iov.iov_len  = sizeof(buffer);

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = 0;
    sa.nl_groups = 0;

    msg.msg_name       = (void *)&sa;
    msg.msg_namelen    = sizeof(sa);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;

    msg.msg_control    = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags      = 0;

    int length = 0;

    if( (length = recvmsg(net_sockfd, &msg, 0)) < 0)
    {
        ERROR_MSG("recvmsg failed");
    }

    for(nh = (struct nlmsghdr *)buffer; NLMSG_OK(nh, length); nh = NLMSG_NEXT(nh, length)) {
        if(nh->nlmsg_type == NLMSG_DONE) {
            break;
        }

        // If link received address
        if( (nh->nlmsg_type == RTM_NEWADDR) ) {
            const struct ifaddrmsg* ifa = (const struct ifaddrmsg*)NLMSG_DATA(nh);
            const struct rtattr* rth    = IFA_RTA(ifa);

            ife = searchLinksByIndex(head_link__, ifa->ifa_index);
            if(!ife) {
                char device[IFNAMSIZ];
                if_indextoname(ifa->ifa_index, device);

                // Check if we should add this device.
                int priority = getLinkPriority(device);
                if(priority < 0) {
                    // Ignore this interface.
                    continue;
                } else {
                    ife = addInterface(device);
                    if(!ife) {
                        DEBUG_MSG("failed to add interface (%s)", device);
                        continue;
                    }

                    ife->ifindex = ifa->ifa_index;
                }
            }

            // Get a static identifier for the network (eg. sprint, verizon)
            // Even if the interface already existed, we need to check this again
            // in case the name changed.
            readNetworkName(ife->ifname, ife->network, sizeof(ife->network));

            int rth_len;
            for(rth_len = IFA_PAYLOAD(nh); rth_len && RTA_OK(rth, rth_len); rth = RTA_NEXT(rth, rth_len)) {
                // Local address changed, make sure RTA_DATA does not return 0.0.0.0 
                // which happens occasionally with the EvDO devices
                if( rth->rta_type == IFA_LOCAL ) {
                    ife->stats.rtm_newaddr_count++;

                    char p_ip[INET6_ADDRSTRLEN]; 
                    inet_ntop(PF_INET, (unsigned*)RTA_DATA(rth), p_ip, sizeof(p_ip));
                    if ( strncmp(p_ip, "0.0.0.0", sizeof(p_ip)) != 0 ) {
                        setLinkIp_p(ife, p_ip);

                        // The IP address just changed, so set to INACTIVE and wait
                        // for pings to go through.
                        DEBUG_MSG("RTM_NEWADDR link (%s) set state to INACTIVE", ife->ifname);
                        enum IF_STATE oldState = setLinkState(ife, INACTIVE);

                        // Check if we need to reactivate lower priority links.
                        if(oldState == ACTIVE) {
                            updateSystemPriorityLevel();
                        }

                        // Send notification if the state changed.
                        if(oldState != INACTIVE) {
                            interface_notify = 1;
                        }

                        // Send a ping immediately for fast connection establishment
                        sendPing(ife);
                    }
                }
            }

        } else if(nh->nlmsg_type == RTM_DELADDR) {
            const struct ifaddrmsg* ifa = (const struct ifaddrmsg*)NLMSG_DATA(nh);
            //const struct rtattr* rth    = IFA_RTA(ifa);

            ife = searchLinksByIndex(head_link__, ifa->ifa_index);
            if(!ife) {
                // Nothing to do since the device was not on our list.
                continue;
            }

            // RTM_DELADDR does not seem to be useful.
            DEBUG_MSG("RTM_DELADDR link (%s)", ife->ifname);

        } else if(nh->nlmsg_type == RTM_NEWLINK) {
            const struct ifinfomsg* ifi = (const struct ifinfomsg*)NLMSG_DATA(nh);

            ife = searchLinksByIndex(head_link__, ifi->ifi_index);
            if(!ife) {
                char device[IFNAMSIZ];
                if_indextoname(ifi->ifi_index, device);

                // Check if we want to add this device.
                int priority = getLinkPriority(device);
                if(priority >= 0) {
                    ife = addInterface(device);
                    if(!ife) {
                        DEBUG_MSG("failed to add interface (%s)", device);
                        continue;
                    }

                    ife->ifindex = ifi->ifi_index;
                } else {
                    // Ignore this interface.
                    continue;
                }
            }

            // Read in the human-readable network name
            readNetworkName(ife->ifname, ife->network, sizeof(ife->network));

            if(!(ifi->ifi_flags & IFF_UP)) {
                // 'ifconfig foo down' will trigger this message for foo
                DEBUG_MSG("RTM_NEWLINK link (%s) set state to DEAD", ife->ifname);
                enum IF_STATE oldState = setLinkState(ife, DEAD);

                // Check if we need to reactivate lower priority links.
                if(oldState == ACTIVE) {
                    updateSystemPriorityLevel();
                }

                // Send a notification if the state changed.
                if(oldState != DEAD) {
                    interface_notify = 1;
                }
            } else if((ifi->ifi_flags & IFF_UP) && (ife->state != INACTIVE)) {
                // 'ifconfig foo up' will trigger this message for foo.  Changing
                // the IP address will also trigger this.
                DEBUG_MSG("RTM_NEWLINK link (%s) set state to INACTIVE", ife->ifname);
                enum IF_STATE oldState = setLinkState(ife, INACTIVE);

                // Check if we need to reactivate lower priority links.
                if(oldState == ACTIVE) {
                    updateSystemPriorityLevel();
                }

                // Send a notification if the state changed.
                if(oldState != INACTIVE) {
                    interface_notify = 1;
                }

                // If link is just coming up, then it does not have
                // a route to the controller.
                addRoute(getControllerIP(), 0, (ife->has_gw ? ife->gw_ip : 0), ife->ifname);

                // Send a ping immediately for fast connection establishment
                sendPing(ife);
            }

        } else if(nh->nlmsg_type == RTM_DELLINK) {
            const struct ifinfomsg* ifi = (const struct ifinfomsg*)NLMSG_DATA(nh);

            ife = searchLinksByIndex(head_link__, ifi->ifi_index);
            if(ife) {
                DEBUG_MSG("RTM_DELLINK setting link (%s) to DEAD", ife->ifname);
                enum IF_STATE oldState = setLinkState(ife, DEAD);

                // Check if we need to reactivate lower priority links.
                if(oldState == ACTIVE) {
                    updateSystemPriorityLevel();
                }

                // Send a notification if the state changed.
                if(oldState != DEAD) {
                    interface_notify = 1;
                }
            }
        }

        if(nh->nlmsg_type == RTM_NEWROUTE)
        {
            struct rtmsg *ifa = (struct rtmsg *)NLMSG_DATA(nh);
            struct rtattr *rth    = RTM_RTA(ifa);

            char dsts[24], ifs[16], ms[24];
            char gws[INET_ADDRSTRLEN];

            memset(dsts, 0, sizeof(dsts));
            memset(ifs, 0, sizeof(ifs));
            memset(ms, 0, sizeof(ms));
            memset(gws, 0, sizeof(gws));

            //DEBUG_MSG("NETLINK: Received RTM_NEWROUTE");
            if( (ifa->rtm_family == AF_INET) && (ifa->rtm_table == RT_TABLE_MAIN) && ifa->rtm_protocol == RTPROT_BOOT) 
            {
                char device[IFNAMSIZ];
                int has_gw = 0;

                int rth_len;
                for(rth_len = RTM_PAYLOAD(nh); rth_len && RTA_OK(rth, rth_len); rth = RTA_NEXT(rth, rth_len))
                {
                    switch(rth->rta_type)
                    {
                        case RTA_DST:
                            inet_ntop(AF_INET, RTA_DATA(rth), dsts, sizeof(dsts));
                            break;
                        case RTA_GATEWAY:
                            inet_ntop(AF_INET, RTA_DATA(rth), gws, sizeof(gws));
                            has_gw = 1;
                            break;
                        case RTA_OIF:
                            sprintf(ifs, "%d", *((int *) RTA_DATA(rth)));
                            if_indextoname(atoi(ifs), device);
                            break;
                        default:
                            break;
                    }
                }

                //printf("RTM_NEWROUTE proto: %d, dev: %s, gw: %s, dst: %s\n", ifa->rtm_protocol, device, gws, dsts);

                struct tunnel *tun = getTunnel();

                // Make sure the route is for a usable device
                if(getLinkPriority(device) >= 0 &&
                        strncmp(device, tun->name, sizeof(device)) != 0) {
                    delRoute("0.0.0.0", "0.0.0.0", 0, device);
                    addRoute(getControllerIP(), 0, (has_gw ? gws : 0), device);

                    // Add the gateway information to the interface
                    ife = searchLinksByName(head_link__, device);
                    if ( ife != NULL ) {
                        ife->has_gw = has_gw;
                        strncpy(ife->gw_ip, gws, sizeof(ife->gw_ip));
                    }
                }
            }
        }
    } // End for loop

    if ( getOpenDNS() == 1 )
        genResolvDotConf();

    unsigned char *unique_id = getUniqueID();
    if ( USE_CONTROLLER && interface_notify && unique_id != NULL)
    {
        // Make sure the tunnel device is set up (which means we have a lease)
        
        //TODO: Race condition, when gateway gets a lease, and this
        //check is enabled, often times the Controller does not receive
        //the notify packet that fires off when the second interface
        //comes up
        
        //if ( getTunPrivIP() != 0 ) 
        //{
            if ( notifyController() < 0 )
            {
                DEBUG_MSG("notifyController() failed");
                STATS_MSG("notifyController() failed");
            }
        //}
    }

    return SUCCESS;
} // End function int handleNetLinkPacket()

