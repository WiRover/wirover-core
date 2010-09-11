#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "contchan.h"
#include "debug.h"
#include "interface.h"
#include "netlink.h"
#include "rootchan.h"
#include "rwlock.h"
#include "utlist.h"

static void* netlink_thread_func(void* arg);
static void add_interface(struct interface* ife);
static void delete_interface(struct interface* ife);
static const char* read_dev_name(const char* __restrict__ buffer, char* __restrict__ dest, int destlen);

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
    FILE* proc_file;
    char buffer[512];

    proc_file = fopen("/proc/net/dev", "r");
    if(!proc_file) {
        ERROR_MSG("Failed to open /proc/net/dev for reading");
        return -1;
    }

    // Throw away the first two lines
    fgets(buffer, sizeof(buffer), proc_file);
    fgets(buffer, sizeof(buffer), proc_file);

    obtain_write_lock(&interface_list_lock);

    while(fgets(buffer, sizeof(buffer), proc_file)) {
        char name[IFNAMSIZ];
        read_dev_name(buffer, name, sizeof(name));

        struct interface* ife;
        ife = alloc_interface();

        ife->index = if_nametoindex(name);
        strncpy(ife->name, name, sizeof(ife->name));

        // Set to INACTIVE until connectivity is confirmed
        ife->state = INACTIVE;

        add_interface(ife);
    }

    release_write_lock(&interface_list_lock);

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
    nladdr.nl_pid    = getpid();
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

    for(nh = (const struct nlmsghdr*)msg; NLMSG_OK(nh, msg_len); nh = NLMSG_NEXT(nh, msg_len)) {
        if(nh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nh);
            //struct rtattr*    rth = IFA_RTA(ifa);

            char device[IFNAMSIZ];
            if_indextoname(ifa->ifa_index, device);

            DEBUG_MSG("Received RTM_NEWADDR for device %s (%d)", device, ifa->ifa_index);

            struct interface* ife;

            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifa_index);
            release_read_lock(&interface_list_lock);

            if(ife) {
                obtain_write_lock(&interface_list_lock);
                ife->state = INACTIVE;
                release_write_lock(&interface_list_lock);
            } else {
                ife = alloc_interface();
                assert(ife);

                ife->index = ifa->ifa_index;
                strncpy(ife->name, device, sizeof(ife->name));
                ife->state = INACTIVE;

                obtain_write_lock(&interface_list_lock);
                add_interface(ife);
                release_write_lock(&interface_list_lock);
            }

            should_notify = 1;
        } else if(nh->nlmsg_type == RTM_DELADDR) {
            struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(nh);
            //struct rtattr*    rth = IFA_RTA(ifa);

            DEBUG_MSG("Received RTM_DELADDR for device %d", ifa->ifa_index);
            
            struct interface* ife;

            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifa_index);
            release_read_lock(&interface_list_lock);

            if(ife) {
                obtain_write_lock(&interface_list_lock);
                delete_interface(ife);
                release_write_lock(&interface_list_lock);
            }

            should_notify = 1;
        } else if(nh->nlmsg_type == RTM_NEWLINK) {
            struct ifinfomsg* ifa = (struct ifinfomsg*)NLMSG_DATA(nh);

            char device[IFNAMSIZ];
            if_indextoname(ifa->ifi_index, device);

            DEBUG_MSG("Received RTM_NEWLINK for device %s (%d)", device, ifa->ifi_index);

            struct interface* ife;

            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifi_index);
            release_read_lock(&interface_list_lock);

            if(ife) {
                obtain_write_lock(&interface_list_lock);
                ife->state = INACTIVE;
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

            should_notify = 1;
        } else if(nh->nlmsg_type == RTM_DELLINK) {
            struct ifinfomsg* ifa = (struct ifinfomsg*)NLMSG_DATA(nh);

            DEBUG_MSG("Received RTM_DELLINK for device %d", ifa->ifi_index);

            struct interface* ife;
            
            obtain_read_lock(&interface_list_lock);
            ife = find_interface_by_index(interface_list, ifa->ifi_index);
            release_read_lock(&interface_list_lock);

            if(ife) {
                obtain_write_lock(&interface_list_lock);
                delete_interface(ife);
                release_write_lock(&interface_list_lock);
            }

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

static void* netlink_thread_func(void* arg)
{
    int sockfd;
    char buffer[4096];

    sockfd = open_netlink_socket();
    if(sockfd == -1) {
        return 0;
    }

    struct iovec iov;
    iov.iov_base = buffer;
    iov.iov_len  = sizeof(buffer);

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
 * READ DEV NAME
 *
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

