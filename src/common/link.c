/*
 * link.c
 */

#include <math.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/if_ether.h> // defines ETH_ALEN

#include "contChan.h"
#include "interface.h"
#include "utils.h"
#include "debug.h"
#include "link.h"
#include "udp_ping.h"

char local_buf[MAX_LINE];

#ifdef GATEWAY
struct link* head_link__ = 0;
#endif

/*
 * MAKE LINK
 *
 * Allocates space for a struct link and initializes it.
 */
struct link* makeLink()
{
    struct link* link = malloc(sizeof(struct link));
    memset(link, 0, sizeof(struct link));

    link->state = DEAD;
    gettimeofday(&link->last_sent,0);
    
    link->que_delay = 0;
    link->curr_weight = 100;
    link->up_weight = 100;
#ifdef GATEWAY
    link->dn_weight = 100;
    link->ping_socket = -1;
#endif

    // Initialize the passive bandwidth stats
    storePassiveStats(link, &link->pstats_running);
    storePassiveStats(link, &link->pstats_recent);

    return link;
}

/*
 * Add a link to the list.  This preserves the ordering of the list by link ID
 * and returns the new head of the list.  Caller must be careful not to add an
 * existing link.
 */
struct link* addLink(struct link* head, struct link* link)
{
    assert(link != 0);

    if(head == 0) {
        return link;
    }

    if(link->id < head->id) {
        // Insert link before the head.
        head->prev = link;
        link->next = head;
        return link;
    }

    struct link *curr = head;
    while(curr->next) {
        if(link->id < curr->next->id) {
            // Insert link between two elements.
            curr->next->prev = link;
            link->next = curr->next;
            link->prev = curr;
            curr->next = link;
            return head;
        }

        assert(curr != curr->next);
        curr = curr->next;
    }

    // Add link to the tail of the list.
    curr->next = link;
    link->prev = curr;
    link->next = 0;
    return head;
}

/*
 * COUNT LINKS
 *
 * Returns the number of links in the list.
 */
unsigned int countLinks(struct link* head)
{
    unsigned int count = 0;

    while(head) {
        count++;

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return count;
}

/*
 * COUNT ACTIVE LINKS
 *
 * Returns the number of links with their state set to ACTIVE.
 */
unsigned int countActiveLinks(struct link* head)
{
    unsigned int count = 0;

    while(head) {
        if(head->state == ACTIVE) {
            count++;
        }

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return count;
}

/*
 * COUNT VALID LINKS
 *
 * Returns the number of links that have a valid (by a crude measure) IP
 * address.
 */
unsigned int countValidLinks(struct link* head)
{
    unsigned int count = 0;

    while(head) {
        if(head->p_ip[0] != 0 &&
                strncmp(head->p_ip, "0.0.0.0", sizeof(head->p_ip))) {
            count++;
        }

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return count;
}

/*
 * FIND ACTIVE LINK
 *
 * Returns the first link that has state set to ACTIVE.
 */
struct link* findActiveLink(struct link* head)
{
    while(head) {
        if(head->state == ACTIVE) {
            return head;
        }

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return 0;
}

/*
 * SEARCH LINKS BY ID
 *
 * Searches for the given link ID.
 *
 * Returns the link or null if it is not found.
 */
struct link* searchLinksById(struct link* head, short id)
{
    while(head) {
        if(head->id == id) {
            return head;
        }

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return 0;
}

/*
 * SEARCH LINKS BY IP
 *
 * p_ip should be a null-terminated char array containing the presentation format
 * IP address as is returned by inet_ntop.
 *
 * Returns the link or null if it is not found.
 */
struct link* searchLinksByIp(struct link* head, char* p_ip)
{
    while(head) {
        if(strncmp(head->p_ip, p_ip, sizeof(head->p_ip)) == 0) {
            return head;
        }

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return 0;
}

/*
 * SEARCH LINKS BY NAME
 */
struct link* searchLinksByName(struct link* head, char* ifname)
{
    while(head) {
        if(strncmp(head->ifname, ifname, sizeof(head->ifname)) == 0) {
            return head;
        }

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return 0;
}
 
/**
 * Searches for the given interface index.  This is useful mainly
 * for handling netlink messages.
 *
 * Returns the link or null if it is not found.
 */
struct link* searchLinksByIndex(struct link* head, int index)
{
    while(head) {
        if(head->ifindex == index) {
            return head;
        }

        assert(head != head->next); //very, very bad
        head = head->next;
    }

    return 0;
}

/*
 * Set the link state and return the previous state.
 */
enum IF_STATE setLinkState(struct link* link, enum IF_STATE state)
{
    assert(link);

    enum IF_STATE oldState = link->state;
    link->state = state;
    return oldState;
}

/*
 * INIT INTERFACE ITERATOR
 *
 * Starts the given iterator at the first available link.  iter must not be
 * null.  After this call, the first link will be available in iter, though it
 * may be null.  head may be null, in which case, initInterfaceIterator will
 * use the head of the main list.  If the wicontroller specifies the head link,
 * the iterator will not iterate over all gateways.
 */
void initInterfaceIterator(struct link_iterator* iter, struct link* head)
{
    assert(iter != 0);

#ifdef CONTROLLER
    if(head) {
        // We will not be iterating over all gateways
        iter->link = head;
        iter->gw = 0;
    } else {
        iter->gw = getHeadGW();

        // Search through the gateway list until we find the first link.
        iter->link = iter->gw ? iter->gw->head_link : 0;
        while(iter->gw != 0 && iter->link == 0) {
            iter->gw = iter->gw->next;

            if(iter->gw) {
                // Get the head link of the new current gateway
                iter->link = iter->gw->head_link;
            }
        }
    }
#else
    iter->link = head ? head : head_link__;
#endif
}

/*
 * NEXT INTERFACE
 *
 * Advances the iterator and returns the current interface.  For the
 * wicontroller, this traverses all interfaces for every gateway.  Returns null
 * after the last interface.  iter must not be null.
 */
struct link* nextInterface(struct link_iterator* iter)
{
    assert(iter != 0);

    if(iter->link) {
        // Advance to the next link
        iter->link = iter->link->next;

#ifdef CONTROLLER
        // Search through the remaining gateways for the next link
        while(iter->gw != 0 && iter->link == 0) {
            // Advance to the next gateway
            iter->gw = iter->gw->next;

            if(iter->gw) {
                // Get the head link of the new current gateway
                iter->link = iter->gw->head_link;
            }
        }
#endif
    }

    return iter->link;
}   

/*
 * DUMP INTERFACES
 *
 * The string prepend will be inserted before every line.  It can be null.
 */
void dumpInterfaces(struct link* head, const char* prepend)
{
    if(!prepend) {
        prepend = "";
    }

    while(head) {
        char* state;
        switch(head->state) {
            case ACTIVE:
                state = "ACTIVE";
                break;
            case INACTIVE:
                state = "INACTIVE";
                break;
            case DEAD:
                state = "DEAD";
                break;
            case STANDBY:
                state = "STANDBY";
                break;
            default:
                state = "UNKNOWN";
                break;
        }

        snprintf(local_buf, sizeof(local_buf),
                 "%sLink %1d) %s / %s (%s:%hu) - State: %s - Weight: %hd - %hd\n",
                 prepend, head->id, head->ifname, head->network, head->p_ip,
                 ntohs(head->data_port), state, head->dn_weight, head->up_weight);
        GENERAL_MSG(local_buf);

        assert(head != head->next); //very, very bad
        head = head->next;
    }
}

/*
 * GET LINK BANDWIDTH DOWN
 */
double getLinkBandwidthDown(struct link* link)
{
    assert(link != 0);
    return link->avg_active_bw_down;
}

/*
 * GET LINK BANDWIDTH UP
 */
double getLinkBandwidthUp(struct link* link)
{
    assert(link != 0);
    return link->avg_active_bw_up;
}

/**
 * Increase the usage counter for the link.
 */
unsigned long long incLinkBytesSent(struct link* link, unsigned long long bytes)
{
    assert(link);

    link->bytes_sent += bytes;
    link->month_sent += bytes;
    return link->bytes_sent;
}

/**
 * Increase the usage counter for the link.
 */
unsigned long long incLinkBytesRecvd(struct link* link, unsigned long long bytes)
{
    assert(link);

    link->bytes_recvd += bytes;
    link->month_recvd += bytes;
    return link->bytes_recvd;
}

/*
 * UPDATE LINK BANDWIDTH
 */
void updateLinkBandwidth(struct link* link, double bw_down, double bw_up)
{
    assert(link != 0);

    if(bw_down <= MAX_BANDWIDTH) {
        if(link->avg_active_bw_down < 0.0001) {
            // probably the first measurement
            link->avg_active_bw_down = bw_down;
        } else {
            link->avg_active_bw_down =
                (1.0 - BANDWIDTH_EMA_WEIGHT) * link->avg_active_bw_down +
                BANDWIDTH_EMA_WEIGHT * bw_down;
        }
    }

    if(bw_up <= MAX_BANDWIDTH) {
        if(link->avg_active_bw_up < 0.0001) {
            // probably the first measurement
            link->avg_active_bw_up = bw_up;
        } else {
            link->avg_active_bw_up =
                (1.0 - BANDWIDTH_EMA_WEIGHT) * link->avg_active_bw_up +
                BANDWIDTH_EMA_WEIGHT * bw_up;
        }
    }
}

/*
 * UPDATE LINK RTT
 */
void updateLinkRtt(struct link* link, struct ping_stats* stats)
{
    assert(link != 0);

    if(stats->rtt > 0) {
        if(link->avg_rtt < 0.0001) {
            // probably the first measurement
            link->avg_rtt  = (double)stats->rtt;
            link->avg_t_ul = (double)stats->t_ul;
        } else {
            link->avg_rtt =
                (1.0 - RTT_EMA_WEIGHT) * link->avg_rtt +
                RTT_EMA_WEIGHT * (double)stats->rtt;
            link->avg_t_ul =
                (1.0 - RTT_EMA_WEIGHT) * link->avg_t_ul +
                RTT_EMA_WEIGHT * (double)stats->t_ul;
        }
    }
}

/*
 * COMPUTE LINK WEIGHTS
 */
void computeLinkWeights(struct link* head)
{
    if(!head) {
        return;
    }

    if(countLinks(head) == 1) {
        head->curr_weight = 1;
        head->up_weight = 1;
        head->dn_weight = 1;
        return;
    }

    double min_down = getLinkBandwidthDown(head);
    double min_up = getLinkBandwidthUp(head);

    struct link* curr = head;
    while(curr) {
        double bw_down = getLinkBandwidthDown(curr);
        if(bw_down < min_down) {
            min_down = bw_down;
        }

        double bw_up = getLinkBandwidthUp(curr);
        if(bw_up < min_up) {
            min_up = bw_up;
        }

        assert(curr != curr->next); //really bad
        curr = curr->next;
    }

    curr = head;
    while(curr) {
        double bw_down = getLinkBandwidthDown(curr);
        double bw_up = getLinkBandwidthUp(curr);

        if(curr->state == ACTIVE) {
            curr->dn_weight = (int)round(bw_down*100 / min_down);
            if(curr->dn_weight <= 0) {
                curr->dn_weight = 1;
            }

         sprintf(local_buf, "For link %d (%s): bw_up is %f, min_up is %f",
                curr->id, curr->ifname, bw_up, min_up);
         DEBUG_MSG(local_buf);
  
          curr->up_weight = (int)round(bw_up*100 / min_up);
            if(curr->up_weight <= 0) {
                curr->up_weight = 1;
            }

            curr->curr_weight = curr->up_weight;
        } else {
            curr->curr_weight = 100;
            curr->up_weight = 100;
            curr->dn_weight = 100;
            break;
        }

//        sprintf(local_buf, "Weight for link %d (%s): %d (v) %d (^)",
//                curr->id, curr->ifname, curr->dn_weight, curr->up_weight);
//        DEBUG_MSG(local_buf);

        curr = curr->next;
    }
}

/*
 * Set link IP from a sockaddr structure (either v4 or v6).
 */
int setLinkIp(struct link *link, const struct sockaddr *addr, socklen_t addrlen)
{
    assert(link && addr);

    int rtn = getnameinfo(addr, addrlen, link->p_ip, sizeof(link->p_ip),
            0, 0, NI_NUMERICHOST);
    if(rtn != 0) {
        DEBUG_MSG("getnameinfo failed: %s", gai_strerror(rtn));
        return FAILURE;
    }
    
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_V4MAPPED;

    struct addrinfo* results = 0;
    rtn = getaddrinfo(link->p_ip, 0, &hints, &results);
    if(rtn != 0) {
        DEBUG_MSG("getaddrinfo failed: %s", gai_strerror(rtn));
        return FAILURE;
    }

    // If getaddrinfo completed successfully, these pointers should not be
    // null, so this assert should never be triggered
    assert(results != 0 && results->ai_addr != 0);

    struct sockaddr_in6* v6addr = (struct sockaddr_in6*)results->ai_addr;
    memcpy(link->n_ip, &v6addr->sin6_addr, sizeof(link->n_ip));
    
    freeaddrinfo(results);

    return SUCCESS;
}

/*
 * SET LINK IP (PRESENTATION)
 *
 * p_ip should be an IP address in presentation format.  It may be either an
 * IPv4 or IPv6 address.  Internally, all addresses are stored in IPv6 format.
 */
int setLinkIp_p(struct link* link, const char* __restrict__ p_ip)
{
    assert(link != 0 && p_ip != 0);
    int rtn;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_V4MAPPED;

    struct addrinfo* results = 0;
    rtn = getaddrinfo(p_ip, 0, &hints, &results);
    if(rtn != 0) {
        sprintf(local_buf, "getaddrinfo failed: %s", gai_strerror(rtn));
        DEBUG_MSG(local_buf);
        return FAILURE;
    }

    // If getaddrinfo completed successfully, these pointers should not be
    // null, so this assert should never be triggered
    assert(results != 0 && results->ai_addr != 0);

    struct sockaddr_in6* addr = (struct sockaddr_in6*)results->ai_addr;
    inet_ntop(AF_INET6, &addr->sin6_addr, link->p_ip, sizeof(link->p_ip));
    memcpy(link->n_ip, &addr->sin6_addr, sizeof(link->n_ip));

    freeaddrinfo(results);

    return SUCCESS;
}

/*
 * SET LINK IP (NETWORK)
 *
 * n_ip should be an IP address in network format.  It must be in IPv6 format,
 * but it can be an IPv4-mapped address.  It is expected to be IP_NETWORK_SIZE
 * (16) bytes.
 */
int setLinkIp_n(struct link* link, const char* __restrict__ n_ip)
{
    assert(link != 0 && n_ip != 0);
    int rtn;

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    memcpy(&addr.sin6_addr, n_ip, sizeof(addr.sin6_addr));

    rtn = getnameinfo((struct sockaddr*)&addr, sizeof(addr), link->p_ip, sizeof(link->p_ip),
                      0, 0, NI_NUMERICHOST);
    if(rtn != 0) {
        sprintf(local_buf, "getnameinfo failed: %s", gai_strerror(rtn));
        DEBUG_MSG(local_buf);
        return FAILURE;
    }

    memcpy(link->n_ip, n_ip, sizeof(link->n_ip));

    return SUCCESS;
}

/*
 * GET LINK IPV4
 *
 * Attempts to produce a network format IPv4 address.
 * Returns 0 if this is not possible.
 */
uint32_t getLinkIpv4(struct link* link)
{
    assert(link != 0);
    int rtn;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_V4MAPPED | NI_NUMERICHOST;

    struct addrinfo* results = 0;
    rtn = getaddrinfo(link->p_ip, 0, &hints, &results);
    if(rtn != 0) {
        sprintf(local_buf, "getaddrinfo failed for %s: %s", link->p_ip, gai_strerror(rtn));
        DEBUG_MSG(local_buf);
        return 0;
    }

    // If getaddrinfo completed successfully, these pointers should not be
    // null, so this assert should never be triggered
    assert(results != 0 && results->ai_addr != 0);

    if(results->ai_family != AF_INET) {
        DEBUG_MSG("Error converting to IPv4 address, are we using IPv6 now?");
        freeaddrinfo(results);
        return 0;
    }

    struct sockaddr_in* addr = (struct sockaddr_in*)results->ai_addr;
    uint32_t ip = addr->sin_addr.s_addr;

    freeaddrinfo(results);
    return ip;
}   

/*
 * READ NETWORK NAME
 *
 * Attempts to read the network name from the filesystem
 * (default location: /var/lib/wirover/networks/).
 *
 * Returns SUCCESS or FAILURE.  Upon failure, the ifname
 * is written to network instead of being read from a file.
 */
int readNetworkName(char* ifname, char* network, unsigned int network_len)
{
    // First zero out the buffer
    memset(network, 0, sizeof(network_len));

    char filename[1000];
    snprintf(filename, sizeof(filename), "%s/%s",
             NETWORK_NAME_PATH, ifname);

    FILE* file = fopen(filename, "r");
    if(!file) {
        strncpy(network, ifname, network_len);
        return FAILURE;
    }

    char* result = fgets(network, network_len, file);
    fclose(file);
    if(!result) {
        strncpy(network, ifname, network_len);
        return FAILURE;
    }

    // If the network name has a newline anywhere, end the string there.
    char* newline = strchr(network, '\n');
    if(newline) {
        *newline = 0;
    }

    return SUCCESS;
}

// vim: set et ts=4 sw=4 cindent:
