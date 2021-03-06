#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>

#include "config.h"
#include "contchan.h"
#include "configuration.h"
#include "debug.h"
#include "interface.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "util.h"
#include "utlist.h"

static void* netlink_thread_func(void* arg);
static void add_interface(struct interface* ife);
static void delete_interface(struct interface* ife);
static int  update_interface_gateways();
static volatile int running = 0;

static pthread_t    netlink_thread;

/*
* INIT INTERFACE LIST
*
* Creates an initial list of interfaces based on those in /proc/net/dev.
*/
int init_interface_list()
{
    struct ifaddrs *ifap_head = NULL;
    struct ifaddrs *ifap = NULL;

    if(getifaddrs(&ifap_head) < 0) {
        ERROR_MSG("getifaddrs failed");
        return -1;
    }

    obtain_write_lock(&interface_list_lock);

    ifap = ifap_head;
    while(ifap) {
        if((ifap->ifa_flags & IFF_UP) && (ifap->ifa_flags & IFF_RUNNING) &&
            !(ifap->ifa_flags & IFF_LOOPBACK)) {
            struct interface *ife;

            ife = find_interface_by_name(interface_list, ifap->ifa_name);
            if(!ife) {
                int priority = get_interface_priority(ifap->ifa_name);
                if(priority < 0)
                    goto next_ifap;

                ife = alloc_interface(get_unique_id());
                if(!ife)
                    goto next_ifap;

                ife->index = if_nametoindex(ifap->ifa_name);
                strncpy(ife->name, ifap->ifa_name, sizeof(ife->name));
                read_network_name(ife->name, ife->network, sizeof(ife->network));

                // Set to INIT_INACTIVE until connectivity is confirmed
                ife->state = INIT_INACTIVE;

                ife->data_port = htons(get_data_port());
                ife->priority = priority;

                add_interface(ife);
            }

            // TODO: Keep IPv6 address(es) as well
            // It seems ifap->ifa_addr can be null, not sure why.
            if(ifap->ifa_addr && ifap->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifap->ifa_addr;
                memcpy(&ife->public_ip, &sin->sin_addr, sizeof(struct sockaddr_in));
            }
        }

    next_ifap:
        ifap = ifap->ifa_next;
    }

    update_interface_gateways();

    release_write_lock(&interface_list_lock);
    freeifaddrs(ifap_head);

    DEBUG_MSG("Initial interface list:");
    dump_interfaces(interface_list, "  ");

    return 0;
}

/*
* CREATE NETLINK THREAD
*/
int create_netlink_thread()
{
    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result;
    running = 1;
    result = pthread_create(&netlink_thread, &attr, netlink_thread_func, 0);
    if(result != 0) {
        ERROR_MSG("creating thread failed");
        return -1;
    }

    pthread_attr_destroy(&attr);
    return 0;
}

/*
* WAIT FOR NETLINK THREAD
*/
int stop_netlink_thread()
{
    running = 0;
    return pthread_join(netlink_thread, 0);
}

/*
* OPEN NETLINK SOCKET
*/
int open_netlink_socket()
{
    int sockfd;

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if(sockfd < 0) {
        ERROR_MSG("creating socket failed");
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 500 * USECS_PER_MSEC;

    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        ERROR_MSG("setsockopt failed");

    // Make the nladdr structure to use for the netlink structure
    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;

    int result;
    result = bind(sockfd, (struct sockaddr*)&nladdr, sizeof(nladdr));
    if(result < 0) {
        ERROR_MSG("binding socket failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/*
* HANDLE NETLINK MESSAGE
*/
int handle_netlink_message(const char* msg, int msg_len)
{
    const struct nlmsghdr* nh;
    struct interface* ife;

    for(nh = (const struct nlmsghdr*)msg; NLMSG_OK(nh, msg_len); nh = NLMSG_NEXT(nh, msg_len)) {
        if(nh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nh);

            char device[IFNAMSIZ];
            if_indextoname(ifa->ifa_index, device);

            DEBUG_MSG("Received RTM_NEWADDR for device %s (%d)", device, ifa->ifa_index);

            obtain_write_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifa_index);

            if(ife) {
                if(ife->state != INIT_INACTIVE) {
                    change_interface_state(ife, INACTIVE);
                }
            }
            else {
                int priority = get_interface_priority(device);
                if(priority >= 0) {
                    ife = alloc_interface(get_unique_id());
                    assert(ife);

                    ife->index = ifa->ifa_index;
                    strncpy(ife->name, device, sizeof(ife->name));
                    ife->state = INIT_INACTIVE;
                    ife->priority = priority;

                    ife->data_port = htons(get_data_port());

                    add_interface(ife);
                }
            }

            if(ife) {
                struct rtattr *rth = IFA_RTA(ifa);
                int rth_len;

                for(rth_len = IFA_PAYLOAD(nh); rth_len && RTA_OK(rth, rth_len);
                    rth = RTA_NEXT(rth, rth_len)) {
                    if(rth->rta_type == IFA_LOCAL) {
                        // Copy the new IP address if it appears valid (non-zero)
                        uint32_t new_ip = *(uint32_t *)RTA_DATA(rth);
                        if(new_ip != 0)
                            ife->public_ip.s_addr = new_ip;
                    }
                }

                read_network_name(ife->name, ife->network, sizeof(ife->network));

                send_ping(ife);
            }

            release_write_lock(&interface_list_lock);
        }
        else if(nh->nlmsg_type == RTM_DELADDR) {
            struct ifaddrmsg* ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);

            DEBUG_MSG("Received RTM_DELADDR for device %d", ifa->ifa_index);
            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifa_index);
            if(ife)
                change_interface_state(ife, INACTIVE);
            release_read_lock(&interface_list_lock);
        }
        else if(nh->nlmsg_type == RTM_DELLINK) {
            struct ifinfomsg* ifi = (struct ifinfomsg *)NLMSG_DATA(nh);

            DEBUG_MSG("Received RTM_DELLINK for device %d", ifi->ifi_index);

            obtain_write_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifi->ifi_index);
            if(ife)
            {
                change_interface_state(ife, DEAD);
                delete_interface(ife);
            }
            release_write_lock(&interface_list_lock);

        }
        else if(nh->nlmsg_type == RTM_NEWROUTE) {
            struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
            struct rtattr *rta = RTM_RTA(rtm);

            if(rtm->rtm_family == AF_INET && rtm->rtm_table == RT_TABLE_MAIN) {
                struct in_addr gwaddr = { .s_addr = 0 };
                int ifindex = 0;

                int dst_set = 0;
                uint32_t dst = 0;
                int ifindex_set = 0;
                int metric_set = 0;
                uint32_t metric = 0;

                int rta_len;
                for(rta_len = RTM_PAYLOAD(nh); rta_len > 0 && RTA_OK(rta, rta_len);
                    rta = RTA_NEXT(rta, rta_len)) {
                    switch(rta->rta_type) {
                    case RTA_GATEWAY:
                        memcpy(&gwaddr, RTA_DATA(rta), sizeof(gwaddr));
                        break;
                    case RTA_OIF:
                        ifindex = *((int *)RTA_DATA(rta));
                        ifindex_set = 1;
                        break;
                    case RTA_DST:
                        memcpy(&dst, RTA_DATA(rta), sizeof(uint32_t));
                        dst_set = 1;
                        break;
                    case RTA_PRIORITY:
                        memcpy(&metric, RTA_DATA(rta), sizeof(uint32_t));
                        metric_set = 1;
                        break;
                    default:
                        break;
                    }
                }
                if(ifindex_set) {
                    obtain_read_lock(&interface_list_lock);
                    struct interface *ife = find_interface_by_index(
                        interface_list, ifindex);
                    if(!dst_set && ife)
                    {
                        DEBUG_MSG("Received RTM_NEWROUTE for default gw on %s", ife->name);
                        if(!metric_set){
                            DEBUG_MSG("Changing priority of new route");
                            delete_route(0, gwaddr.s_addr, 0, ife->name);
                            add_route(0, gwaddr.s_addr, 0, 100, ife->name);
                        }
                    }
                    release_read_lock(&interface_list_lock);
                }
            }
        }
        else if(nh->nlmsg_type == RTM_DELROUTE) {
            struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
            struct rtattr *rta = RTM_RTA(rtm);

            if(rtm->rtm_family == AF_INET && rtm->rtm_table == RT_TABLE_MAIN) {
                struct in_addr dstaddr = { .s_addr = 0 };
                int ifindex = 0;
                int ifindex_set = 0;

                int rta_len;
                for(rta_len = RTM_PAYLOAD(nh); rta_len > 0 && RTA_OK(rta, rta_len);
                    rta = RTA_NEXT(rta, rta_len)) {
                    switch(rta->rta_type) {
                    case RTA_DST:
                        memcpy(&dstaddr, RTA_DATA(rta), sizeof(dstaddr));
                        break;
                    case RTA_OIF:
                        ifindex = *((int *)RTA_DATA(rta));
                        ifindex_set = 1;
                        break;
                    default:
                        break;
                    }
                }

                /* If a default route for one of our slave devices was deleted,
                * then this is a signal that the interface should be marked
                * INACTIVE.
                *
                * For anything other than a default route, dstaddr will be set
                * to a non-zero value. */
                if(ifindex_set && dstaddr.s_addr == 0) {
                    char dstaddr_p[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &dstaddr, dstaddr_p, sizeof(dstaddr_p));

                    obtain_read_lock(&interface_list_lock);

                    struct interface *ife = find_interface_by_index(
                        interface_list, ifindex);
                    if(ife) {
                        DEBUG_MSG("RTM_DELROUTE dst %s dev %s",
                            dstaddr_p, ife->name);

                        if(ife->state == ACTIVE) {
                            change_interface_state(ife, INACTIVE);
                        }
                    }

                    release_read_lock(&interface_list_lock);
                }
            }
        }
    }

    return 0;
}


/*
* The network name is a descriptive name for an interface such as "verizon" or
* "sprint" as opposed to interface names such as "ppp0" or "ppp1".  The
* network name is used for data collection.  This will attempt to read the
* network name for an interface from a file (by default in
* /var/lib/wirover/networks).  If successful, the network name is copied into
* dest, otherwise ifname is copied into dest.
*/
void read_network_name(const char * __restrict__ ifname,
    char * __restrict__ dest, int destlen)
{
    char filename[256];
    snprintf(filename, sizeof(filename), NETWORK_NAME_PATH "/%s", ifname);

    FILE *file = fopen(filename, "r");
    if(!file) {
        strncpy(dest, ifname, destlen);
        return;
    }

    if(!fgets(dest, destlen, file)) {
        DEBUG_MSG("failed to read %s", filename);
        strncpy(dest, ifname, destlen);
    }

    fclose(file);

    int i;
    for(i = 0; i < destlen; i++) {
        if(isspace(dest[i]))
            dest[i] = 0;
        if(!dest[i])
            break;
    }
}

static void* netlink_thread_func(void* arg)
{
    int sockfd;

    char *buffer = malloc(NETLINK_BUFFER_SIZE);
    if(!buffer) {
        DEBUG_MSG("out of memory");
        return 0;
    }

    sockfd = open_netlink_socket();
    if(sockfd == -1) {
        free(buffer);
        return 0;
    }

    struct iovec iov;
    iov.iov_base = buffer;
    iov.iov_len = NETLINK_BUFFER_SIZE;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    struct msghdr msg;
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    while(running) {
        int length;

        length = recvmsg(sockfd, &msg, 0);
        if(length < 0) {
            if(errno == EAGAIN || errno == EINTR) { continue; }
            ERROR_MSG("Receiving message failed");
        }
        else {
            handle_netlink_message(buffer, length);
        }
    }

    obtain_write_lock(&interface_list_lock);
    struct interface *current, *tmp;

    DL_FOREACH_SAFE(interface_list, current, tmp) {
        delete_interface(current);
    }

    release_write_lock(&interface_list_lock);

    close(sockfd);
    free(buffer);

    return 0;
}

static void add_interface(struct interface* ife)
{
    DEBUG_MSG("Adding interface %s", ife->name);
    interface_bind(ife, get_data_port());
    DL_APPEND(interface_list, ife);
}

static void delete_interface(struct interface* ife)
{
    DEBUG_MSG("Deleting interface %s", ife->name);
    DL_DELETE(interface_list, ife);
    free_interface(ife);
}

/*
* Read the routing table for gateway IP addresses and update interface list.
*
* Locking: Assumes a write lock is held on the gateway list.
*/
static int update_interface_gateways()
{
    const char *delims = "\t ";

    FILE *file = fopen("/proc/net/route", "r");
    if(!file) {
        ERROR_MSG("Failed to open /proc/net/route");
        return -1;
    }

    char buffer[256];

    // Skip the header line
    fgets(buffer, sizeof(buffer), file);

    char *saveptr = 0;

    while(!feof(file) && fgets(buffer, sizeof(buffer), file)) {
        buffer[sizeof(buffer) - 1] = 0;

        char *device = strtok_r(buffer, delims, &saveptr);
        if(!device)
            continue;

        char *dest = strtok_r(0, delims, &saveptr);
        if(!dest)
            continue;

        char *gateway = strtok_r(0, delims, &saveptr);
        if(!gateway)
            continue;

        uint32_t dest_ip = (uint32_t)strtoul(dest, 0, 16);
        uint32_t gateway_ip = (uint32_t)strtoul(gateway, 0, 16);

        struct interface *ife = find_interface_by_name(interface_list, device);
        if(ife && dest_ip == 0 && gateway_ip != 0) {
            ife->gateway_ip.s_addr = gateway_ip;
            DEBUG_MSG("Found gateway 0x%x for %s", ntohl(gateway_ip), device);
        }
    }

    fclose(file);
    return 0;
}

