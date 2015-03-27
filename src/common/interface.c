#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "configuration.h"
#include "datapath.h"
#include "debug.h"
#include "interface.h"
#include "rateinfer.h"
#include "rwlock.h"
#include "packet_buffer.h"
#include "timing.h"
#ifdef GATEWAY
#include "contchan.h"
#include "util.h"
#endif

struct interface*   interface_list = 0;
struct rwlock       interface_list_lock = RWLOCK_INITIALIZER;
int ping_interval = -1;
int ping_timeout = -1;

/*
* ALLOC INTERFACE
*
* Allocate and initialize an interface structure.
*/
struct interface* alloc_interface(int node_id)
{
    struct interface* ife;

    ife = (struct interface*)malloc(sizeof(struct interface));
    assert(ife);

    memset(ife, 0, sizeof(*ife));
    ife->node_id = node_id;
    ife->avg_rtt = NAN;
    ife->avg_downlink_bw = NAN;
    ife->avg_uplink_bw = NAN;

    get_monotonic_time(&ife->rx_time);
    get_monotonic_time(&ife->tx_time);

    if(ping_interval == -1)
        ping_interval = get_ping_interval();
    ife->ping_interval = ping_interval;
    if(ping_timeout == -1)
        ping_timeout = get_ping_timeout();
    ife->ping_timeout = ping_timeout;

    // Prevent early timeouts
    struct timeval now;
    get_monotonic_time(&now);
    ife->last_ping_time = now;
    ife->last_ping_success = now;
    struct rwlock lock = RWLOCK_INITIALIZER;
    ife->rt_buffer.rwlock = lock;

    rc_init(&ife->ingress_rate_control, 10, 20000, 1.0);
    rc_init(&ife->egress_rate_control, 10, 20000, 1.0);
    cbuffer_init(&ife->rtt_buffer, 10, 20000);

    return ife;
}

/*
* Sets the interface's state to the given state, and if there was a change
* between ACTIVE and non-ACTIVE states on a gateway, it notifies the controller
*/
int change_interface_state(struct interface *ife, enum if_state state)
{
    if(ife->state == state)
    return 0;
    DEBUG_MSG("Changing interface %s state from %d to %d", ife->name, ife->state, state);
    ife->state = state;
    if(state == INACTIVE)
    {
        DEBUG_MSG("Retransmitting %d unacked packets", ife->rt_buffer.length);
        while(ife->rt_buffer.length > 0) {
            //TODO: Switch retransmit buffer to use struct packet
            //send_packet(ife->rt_buffer.head->packet, ife->rt_buffer.head->size);
            pb_free_head(&ife->rt_buffer);
        }
    }
#ifdef GATEWAY
    send_notification(1);
#endif
    return 0;
}

void update_interface_public_address(struct interface *ife, const struct sockaddr *from, socklen_t from_len)
{
    // TODO: Add IPv6 support
    struct sockaddr_in from_in;

    if(sockaddr_to_sockaddr_in(from, sizeof(struct sockaddr), &from_in) < 0) {
        char p_ip[INET6_ADDRSTRLEN];
        getnameinfo(from, from_len, p_ip, sizeof(p_ip), 0, 0, NI_NUMERICHOST);

        DEBUG_MSG("Unable to add interface with address %s (IPv6?)", p_ip);
        return;
    }

    /* The main reason for this check is if the remote_node is behind a NAT,
    * then the IP address and port that it sends in its notification are
    * not the same as its public IP address and port. */
    if(memcmp(&ife->public_ip, &from_in.sin_addr, sizeof(struct in_addr)) ||
        ife->data_port != from_in.sin_port) {
            DEBUG_MSG("Changing node %hu link %hu from %x:%hu to %x:%hu",
                ife->node_id, ife->index,
                ntohl(ife->public_ip.s_addr), ntohs(ife->data_port),
                ntohl(from_in.sin_addr.s_addr), ntohs(from_in.sin_port));

            memcpy(&ife->public_ip, &from_in.sin_addr, sizeof(struct in_addr));
            ife->data_port  = from_in.sin_port;

            /* We now know that ife->public_ip and ife->data_port are correct. */
            ife->flags |= IFFLAG_SOURCE_VERIFIED;

#ifdef CONTROLER
#ifdef WITH_DATABASE
            db_update_link(gw, ife);
#endif
#endif
    } else if((ife->flags & IFFLAG_SOURCE_VERIFIED) == 0) {
        /* The source was correct, but now we can say it has been verified. */
        ife->flags |= IFFLAG_SOURCE_VERIFIED;
    }
}

static int configure_socket(int sock_type, int proto, const char * ife_name, int bind_port, int reuse, int ip_hdrincl) {
    int sockfd;
    if((sockfd = socket(AF_INET, sock_type, proto)) < 0) 
    {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }
    int on = 1;
    if(reuse) {
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 )
        {
            ERROR_MSG("setsockopt SO_REUSEADDR failed");
            close(sockfd);
            return FAILURE;
        }
    }
    if(ip_hdrincl)
    {
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0 )
        {
            ERROR_MSG("setsockopt IP_HDRINCL failed");
            close(sockfd);
            return FAILURE;
        }
    }
    if(strlen(ife_name) != 0){
        if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ife_name, IFNAMSIZ) < 0) 
        {
            ERROR_MSG("setsockopt SO_BINDTODEVICE failed");
            close(sockfd);
            return FAILURE;
        }
        DEBUG_MSG("Bound socket %d to device %s", sockfd, ife_name);
    }
    
    struct sockaddr_in myAddr;
    memset(&myAddr, 0, sizeof(struct sockaddr_in));
    myAddr.sin_family      = AF_INET;
    myAddr.sin_port        = htons((unsigned short)bind_port);
    myAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(sockfd, (struct sockaddr *)&myAddr, sizeof(struct sockaddr_in)) < 0) 
    {
        ERROR_MSG("bind socket failed");
        close(sockfd);
        return FAILURE;
    }
    return sockfd;
}

int interface_bind(struct interface *ife, int bind_port)
{
    ife->sockfd = configure_socket(SOCK_DGRAM, 0, ife->name, bind_port, 1, 0);
    if(ife->sockfd == FAILURE) { return FAILURE; }

    ife->raw_sockfd = configure_socket(SOCK_RAW, IPPROTO_RAW, ife->name, 0, 0, 1);
    if(ife->raw_sockfd == FAILURE) { return FAILURE; }

#ifdef GATEWAY
	if (drop_tcp_rst(ife->name) == FAILURE) {
		DEBUG_MSG("Couldn't drop RST packets for device");
	}
#endif
    return SUCCESS;
} // End function int interfaceBind()

/*
* FREE INTERFACE
*
* Frees memory used by the interface structure.  If the interface is contained
* in any data structures, this will NOT update them.
*/
void free_interface(struct interface* ife)
{
    if(ife) {
#ifdef GATEWAY
        remove_drop_tcp_rst(ife->name);
#endif
        free(ife);
    }
}

struct interface *find_interface_by_index(struct interface *head, unsigned int index)
{
    while(head) {
        if(head->index == index) {
            return head;
        }

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_interface_by_name(struct interface *head, const char *name)
{
    assert(name);

    while(head) {
        if(!strncmp(head->name, name, sizeof(head->name))) {
            return head;
        }

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_interface_by_network(struct interface *head, const char *network)
{
    assert(network);

    while(head) {
        if(!strncmp(head->network, network, sizeof(head->name))) {
            return head;
        }

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_interface_at_pos(struct interface *head, unsigned pos)
{
    unsigned i = 0;

    while(head) {
        if(i == pos)
            return head;

        i++;

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

struct interface *find_active_interface(struct interface *head)
{
    while(head) {
        if(head->state == ACTIVE)
            return head;

        assert(head != head->next);
        head = head->next;
    }

    return 0;
}

int max_active_interface_priority(struct interface *head)
{
    int max_priority = -1;
    while(head) {
        if(head->state == ACTIVE && head->priority > max_priority)
            max_priority = head->priority;

        assert(head != head->next);
        head = head->next;
    }

    return max_priority;
}

int count_all_interfaces(const struct interface *head)
{
    int count = 0;

    while(head) {
        count++;

        assert(head != head->next);
        head = head->next;
    }

    return count;
}

int count_active_interfaces(const struct interface *head)
{
    int num_active = 0;

    while(head) {
        if(head->state == ACTIVE)
            num_active++;

        assert(head != head->next);
        head = head->next;
    }

    return num_active;
}

/*
* Creates an array containing information about every interface.  This is
* useful for performing an action that would otherwise require the interface
* list to be locked for a long period of time.
*
* Returns the number of interfaces or -1 on memory allocation failure.  A
* return value of > 0 implies that *out points to an array of interface_copy
* structures.  Remember to free it.
*/
int copy_all_interfaces(const struct interface *head, struct interface_copy **out)
{
    assert(out);

    int n = count_all_interfaces(head);
    if(n == 0)
        return 0;

    unsigned alloc_size = sizeof(struct interface_copy) * n;
    *out = malloc(alloc_size);
    if(!*out) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    memset(*out, 0, alloc_size);

    int i = 0;
    while(head && i < n) {
        (*out)[i].index = head->index;
        strncpy((*out)[i].name, head->name, IFNAMSIZ);

        i++;
        head = head->next;
    }

    return n;
}

/*
* Creates an array containing information about every active interface.  This
* is useful for performing an action that would otherwise require the
* interface list to be locked for a long period of time.
*
* Returns the number of active interfaces or -1 on memory allocation failure.
* A return value of > 0 implies that *out points to an array of interface_copy
* structures.  Remember to free it.
*/
int copy_active_interfaces(const struct interface *head, struct interface_copy **out)
{
    assert(out);

    int num_active = count_active_interfaces(head);
    if(num_active == 0)
        return 0;

    unsigned alloc_size = sizeof(struct interface_copy) * num_active;
    *out = malloc(alloc_size);
    if(!*out) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    memset(*out, 0, alloc_size);

    int i = 0;
    while(head && i < num_active) {
        if(head->state == ACTIVE) {
            (*out)[i].index = head->index;
            strncpy((*out)[i].name, head->name, IFNAMSIZ);
            i++;
        }

        head = head->next;
    }

    return num_active;
}

double calc_bw_up(const struct interface *ife)
{
    return ife->est_uplink_bw * .5 + ife->meas_bw_up * .5;
}

double calc_bw_down(const struct interface *ife)
{
    return ife->est_downlink_bw * .5 + ife->meas_bw_down * .5;
}

/*
* Performs an exponential weighted moving average.  If the old value is NaN, 
* then it is assumed that new_val is the first value in the sequence.
*/
double ewma_update(double old_val, double new_val, double new_weight)
{
    if(isnan(old_val)) {
        return new_val;
    } else {
        return ((1.0 - new_weight) * old_val + new_weight * new_val);
    }
}
int interface_to_string(const struct interface *ife, char *str, int size)
{
    const char *state;
    switch(ife->state) {
    case INIT_INACTIVE:
        state = "INIT";
        break;
    case ACTIVE:
        state = "ACTIVE";
        break;
    case INACTIVE:
        state = "INACTIVE";
        break;
    case DEAD:
        state = "DEAD";
        break;
    default:
        state = "UNKNOWN";
        break;
    }
    ipaddr_t addr;
    char ip_string[INET6_ADDRSTRLEN];
    ipv4_to_ipaddr(ife->public_ip.s_addr, &addr);
    ipaddr_to_string(&addr, ip_string, INET6_ADDRSTRLEN);

    return snprintf(str, size, "%-3d %-8s %-12s %-8s %-4hhd %-5hhd %-10lu %-10lu %-15s %-10f %-10f",
        ife->index, ife->name, ife->network, state, ife->priority, ife->packets_since_ack, 
        ife->tx_bytes, ife->rx_bytes, ip_string, calc_bw_up(ife), calc_bw_down(ife));
}
void dump_interface(const struct interface *ife, const char *prepend)
{
    char buffer[128];
    interface_to_string(ife, buffer, sizeof(buffer));
    DEBUG_MSG(" %s%s",
        prepend, buffer);
}
int dump_interfaces_to_file(const struct interface *head, const char *filename)
{
    FILE *ife_file = fopen(filename, "w");
    if(ife_file == NULL)
        return FAILURE;
    fprintf(ife_file, "%s\n", "ID  Name     Network      State    Prio Unack TX_Bytes   RX_Bytes   IP              BW_Up      BW_Down   ");
    char buffer[128];
    while(head) {
        interface_to_string(head, buffer, sizeof(buffer));
        fprintf(ife_file, "%s\n", buffer);
        assert(head != head->next);
        head = head->next;
    }
    fclose(ife_file);
    return SUCCESS;
}
void dump_interfaces(const struct interface *head, const char *prepend)
{
    if(!prepend)
        prepend = "";

    /*           xxx xxxxxxxx xxxxxxxxxxxx xxxxxxxx xxxx xxxxx xxxxxxxxxx xxxxxxxxxx xxxxxxxxxxxxxxx xxxxxxxxxx xxxxxxxxxx*/
    DEBUG_MSG("%sID  Name     Network      State    Prio Unack TX_Bytes   RX_Bytes   IP              BW_Up      BW_Down   ", prepend);

    while(head) {
        dump_interface(head, prepend);
        assert(head != head->next);
        head = head->next;
    }
}

