#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "configuration.h"
#include "datapath.h"
#include "debug.h"
#include "interface.h"
#include "rwlock.h"
#include "packet_buffer.h"
#ifdef GATEWAY
#include "contchan.h"
#endif

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

    gettimeofday(&ife->rx_time, NULL);
    gettimeofday(&ife->tx_time, NULL);

    ife->ping_interval = get_ping_interval();
    ife->ping_timeout = get_ping_timeout();

    // Prevent early timeouts
    struct timeval now;
    gettimeofday(&now, NULL);
    ife->last_ping_time = now;
    ife->last_ping_success = now;
    struct rwlock lock = RWLOCK_INITIALIZER;
    ife->rt_buffer.rwlock = lock;

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
            send_packet(ife->rt_buffer.head->packet, ife->rt_buffer.head->size);
            pb_free_head(&ife->rt_buffer);
        }
    }
#ifdef GATEWAY
    send_notification(1);
#endif
    return 0;
}

int interface_bind(struct interface *ife, int bind_port)
{
    struct sockaddr_in myAddr;
    int sockfd;

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    memset(&myAddr, 0, sizeof(struct sockaddr_in));
    myAddr.sin_family      = AF_INET;
    myAddr.sin_port        = htons((unsigned short)bind_port);
    myAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int on = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 )
    {
        ERROR_MSG("setsockopt SO_REUSEADDR failed");
        close(sockfd);
        return FAILURE;
    }

    if(strlen(ife->name) != 0){
        if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ife->name, IFNAMSIZ) < 0) 
        {
            ERROR_MSG("setsockopt SO_BINDTODEVICE failed");
            close(sockfd);
            return FAILURE;
        }
    }

    if(bind(sockfd, (struct sockaddr *)&myAddr, sizeof(struct sockaddr_in)) < 0) 
    {
        ERROR_MSG("bind socket failed");
        close(sockfd);
        return FAILURE;
    }

    ife->sockfd = sockfd;

    return sockfd;
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

long calc_bw_hint(struct interface *ife)
{
    long bw_hint;
    
    bw_hint = ife->est_uplink_bw * 1000000 + ife->est_downlink_bw * 1000000;
    /*if(ife->meas_bw > 0 && ife->pred_bw > 0) {
        double w = exp(BANDWIDTH_MEASUREMENT_DECAY * 
            (time(NULL) - ife->meas_bw_time));
        bw_hint = (long)round(w * ife->meas_bw + (1.0 - w) * ife->pred_bw);
    } else if(ife->meas_bw > 0) {
        bw_hint = ife->meas_bw;
    } else if(ife->pred_bw > 0) {
        bw_hint = ife->pred_bw;
    } else {
        bw_hint = 0;
    }*/

    return bw_hint;
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

    return snprintf(str, size, "%-3d %-8s %-12s %-8s %-4hhd %-5hhd %-10d %-10d %-15s %-10f %-10f",
        ife->index, ife->name, ife->network, state, ife->priority, ife->packets_since_ack, 
        ife->tx_bytes, ife->rx_bytes, ip_string, ife->est_uplink_bw, ife->est_downlink_bw);
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
    fprintf(ife_file, "%s\n", "ID  Name     Network      State    Prio Unack TX_Bytes   RX_Bytes   IP              BW Up      BW Down   ");
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
    DEBUG_MSG("%sID  Name     Network      State    Prio Unack TX_Bytes   RX_Bytes   IP              BW Up      BW Down   ", prepend);

    while(head) {
        dump_interface(head, prepend);
        assert(head != head->next);
        head = head->next;
    }
}

