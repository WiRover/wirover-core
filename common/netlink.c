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

#include "config.h"
#include "contchan.h"
#include "configuration.h"
#include "debug.h"
#include "interface.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "utlist.h"
#include "kernel.h"

static void* netlink_thread_func(void* arg);
static void add_interface(struct interface* ife);
static void delete_interface(struct interface* ife);
static const char* read_dev_name(const char* __restrict__ buffer, char* __restrict__ dest, int destlen);
static int  update_interface_gateways();

struct interface*   interface_list = 0;
struct rwlock       interface_list_lock = RWLOCK_INITIALIZER;

static pthread_t    netlink_thread;

/*
 * INIT INTERFACE LIST
 *
 * Creates an initial list of interfaces based on those in /proc/net/dev.
 */
int init_interface_list()
{
    struct ifaddrs *ifap = 0;
    if(getifaddrs(&ifap) < 0) {
        ERROR_MSG("getifaddrs failed");
        return -1;
    }

    obtain_write_lock(&interface_list_lock);

    while(ifap) {
        if((ifap->ifa_flags & IFF_UP) && (ifap->ifa_flags & IFF_RUNNING) &&
                !(ifap->ifa_flags & IFF_LOOPBACK)) {
            struct interface *ife;

            ife = find_interface_by_name(interface_list, ifap->ifa_name);
            if(!ife) {
                int priority = get_interface_priority(ifap->ifa_name);
                if(priority < 0)
                    continue;

                ife = alloc_interface();
                if(!ife)
                    continue;

                ife->index = if_nametoindex(ifap->ifa_name);
                strncpy(ife->name, ifap->ifa_name, sizeof(ife->name));

                // Set to INACTIVE until connectivity is confirmed
                ife->state = INACTIVE;

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
        
        ifap = ifap->ifa_next;
    }

    update_interface_gateways();

    release_write_lock(&interface_list_lock);
    freeifaddrs(ifap);

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
int wait_for_netlink_thread()
{
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

    // Make the nladdr structure to use for the netlink structure
    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid    = 0;
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
    int should_notify = 0;
    struct interface* ife;

    for(nh = (const struct nlmsghdr*)msg; NLMSG_OK(nh, msg_len); nh = NLMSG_NEXT(nh, msg_len)) {
        if(nh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nh);
            //struct rtattr*    rth = IFA_RTA(ifa);

            char device[IFNAMSIZ];
            if_indextoname(ifa->ifa_index, device);

            DEBUG_MSG("Received RTM_NEWADDR for device %s (%d)", device, ifa->ifa_index);

            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifa_index);

            if(ife) {
                upgrade_read_lock(&interface_list_lock);
                change_interface_state(ife, INACTIVE);
                downgrade_write_lock(&interface_list_lock);
            } else {
                int priority = get_interface_priority(device);
                if(priority >= 0) {
                    ife = alloc_interface();
                    assert(ife);

                    ife->index = ifa->ifa_index;
                    strncpy(ife->name, device, sizeof(ife->name));
                    ife->state = INACTIVE;
                    ife->priority = priority;

                    upgrade_read_lock(&interface_list_lock);
                    add_interface(ife);
                    downgrade_write_lock(&interface_list_lock);
                }
            }

            ping_interface(ife);
            release_read_lock(&interface_list_lock);

            should_notify = 1;
        } else if(nh->nlmsg_type == RTM_DELADDR) {
            struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nh);
            //struct rtattr*    rth = IFA_RTA(ifa);

            DEBUG_MSG("Received RTM_DELADDR for device %d", ifa->ifa_index);

/*
            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifi_index);
            release_read_lock(&interface_list_lock);

            if(ife) {
                obtain_write_lock(&interface_list_lock);
                change_interface_state(ife, INACTIVE);
                release_write_lock(&interface_list_lock);
            } else {
                ife = alloc_interface(device);
                assert(ife);

                ife->index = ifa->ifi_index;
                strncpy(ife->name, device, sizeof(ife->name));
                ife->state = INACTIVE;

                obtain_write_lock(&interface_list_lock);
                add_interface(ife);
                release_write_lock(&interface_list_lock);
            }

            should_notify = 1; */
        } else if(nh->nlmsg_type == RTM_DELLINK) {
            struct ifinfomsg* ifa = (struct ifinfomsg*)NLMSG_DATA(nh);

            DEBUG_MSG("Received RTM_DELLINK for device %d", ifa->ifi_index);

            struct interface* ife;
            
            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifi_index);

            if(ife) {
                upgrade_read_lock(&interface_list_lock);

                change_interface_state(ife, DEAD);
                delete_interface(ife);

                downgrade_write_lock(&interface_list_lock);
            }

            release_read_lock(&interface_list_lock);
            
            should_notify = 1;
        } else if(nh->nlmsg_type == RTM_NEWROUTE) {
            DEBUG_MSG("Received RTM_NEWROUTE");
        }
    }

    const struct lease_info* lease = get_lease_info();
    if(should_notify && lease != 0) {
        send_notification(lease);
    }

    return 0;
}

/*
 * Sets the interface's state to the given state, and if there was a change
 * between ACTIVE and non-ACTIVE states, it makes the appropriate ioctl()
 * calls.
 */
int change_interface_state(struct interface* ife, enum if_state state)
{
    if(ife->state != ACTIVE && state == ACTIVE) {
        ife->state = state;

#ifdef WITH_KERNEL
        if(kernel_enslave_device(ife->name) == FAILURE) {
            DEBUG_MSG("Failed to enslave device");
            return FAILURE;
        }
#endif
    } else if(ife->state == ACTIVE && state != ACTIVE) {
        ife->state = state;

#ifdef WITH_KERNEL
        if(kernel_release_device(ife->name) == FAILURE) {
            DEBUG_MSG("Failed to release device");
            return FAILURE;
        }
#endif
    }

    return 0;
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
    iov.iov_len  = NETLINK_BUFFER_SIZE;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid    = 0;
    sa.nl_groups = 0;

    struct msghdr msg;
    msg.msg_name       = &sa;
    msg.msg_namelen    = sizeof(sa);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = 0;
    msg.msg_controllen = 0;
    msg.msg_flags      = 0;

    while(1) {
        int length;

        length = recvmsg(sockfd, &msg, 0);
        if(length < 0) {
            ERROR_MSG("Receiving message failed");
        } else {
            handle_netlink_message(buffer, length);
        }
    }

    close(sockfd);
    free(buffer);

    return 0;
}

static void add_interface(struct interface* ife)
{
    DEBUG_MSG("Adding interface %s", ife->name);
    DL_APPEND(interface_list, ife);
}

static void delete_interface(struct interface* ife)
{
    DEBUG_MSG("Deleting interface %s", ife->name);
    DL_DELETE(interface_list, ife);
    free(ife);
}

/*
 * Reads the device name from a line from /proc/net/dev.
 *
 * Returns a pointer to the next character after the name.
 */
static const char* read_dev_name(const char* __restrict__ buffer, char* __restrict__ dest, int destlen)
{
    memset(dest, 0, destlen);

    int i = 0;
    while(isspace(buffer[i])) {
        i++;
    }

    // Hit the end of the string -- this would be very unusual.
    if(buffer[i] == 0) {
        return &buffer[i];
    }

    int j = 0;
    while(isalnum(buffer[i]) && j < destlen - 1) {
        dest[j++] = buffer[i++];
    }

    return &buffer[i];
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

        uint32_t dest_ip    = (uint32_t)strtoul(dest, 0, 16);
        uint32_t gateway_ip = (uint32_t)strtoul(gateway, 0, 16);

        struct interface *ife = find_interface_by_name(interface_list, device);
        if(ife && dest_ip == 0 && gateway_ip != 0) {
            ife->gateway_ip.s_addr = gateway_ip;
            DEBUG_MSG("Found gateway 0x%x for %s", ntohl(gateway_ip), device);

            virt_set_gateway_ip(device, &ife->gateway_ip);
        }
    }

    fclose(file);
    return 0;
}

