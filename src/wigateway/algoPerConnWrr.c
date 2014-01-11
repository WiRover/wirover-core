#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <netdb.h>      /* Transform the ip address string to real number*/
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <search.h>
#include <time.h>
#include <sys/time.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/utils.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/packet_debug.h"
#include "../common/uthash.h"
#include "../common/sockets.h"

/* TODO: list
 * - need a better way to check timeouts than calling gettimeofday for every packet
 * - should DNS be sent out the same connection as the following tcp flow?
 * - should the controller send traffic back on same link?
 */

typedef enum connState {
    CONNECTED=1,
    CONNECTING,
    CLOSING,
    CLOSED
}connState;

struct tuple {
    struct in6_addr destAddr;
    struct in6_addr srcAddr;
    unsigned short destPort;
    unsigned short srcPort;
    unsigned short proto;
};

struct hashentry {
    struct link *conn_if;
    connState state;
    struct timeval time;

    // Some requirements of uthash are that we zero-fill the key (specifically,
    // the padding) before use and that we never modify the key while the entry
    // is stored in the table.
    struct tuple key;
	UT_hash_handle hh; //needed for uthash
};

#define STALE_THRESH 5

struct hashentry* table = NULL;

struct link *getConnInterface(struct link *list);
struct link *handleTCP(struct link *list, const struct tcphdr *tcphdr, 
        struct tuple *tuple);
struct link *handleUDP(struct link *list, struct tuple *tuple);
static int makeFlowTuple(const struct iphdr *iphdr, int proto, const void *t_hdr, 
        struct tuple *tuple);

struct link *algoPerConnWrr(struct link *list, const char *pkt, int len)
{
    int th_offset;
    int proto = find_transport_header(pkt, len, &th_offset);
    if(proto < 0) {
        DEBUG_MSG("find_transport_header failed");
        return 0;
    }
    
    struct tuple tuple;
    if(makeFlowTuple((const struct iphdr *)pkt, proto, 
                pkt + th_offset, &tuple) == FAILURE) {
        DEBUG_MSG("makeFlowTuple failed");
        return 0;
    }

    switch(tuple.proto)
    {
        case IPPROTO_TCP:
        {
            //call tcp handler
            const struct tcphdr *tcphdr = (const struct tcphdr *)
                (pkt + th_offset);
            return handleTCP(list, tcphdr, &tuple);
        }

        case IPPROTO_UDP:
        {
            //call udp handler
            return handleUDP(list, &tuple);
        }

        default:
        {
            //just return an interface
            return getConnInterface(list);
        }
    }

    return 0;
}


struct link *getConnInterface(struct link *list)
{
    struct link *ptr = list;

    //add up the weights for active interfaces
    int total_weight = 0;
    while(ptr)
    {
        if( ptr->state == ACTIVE )
        {
            total_weight += ptr->up_weight;
        }
        ptr = ptr->next;
    }

    if(total_weight == 0) {
        DEBUG_MSG("no available interfaces");
        return 0;
    }

    //generate a random number
    int index = 0;
    //srand( time(NULL) );
    index = rand() % total_weight;
    //printf("index is: %d total_weight is: %d\n", index, total_weight);

    //loop through and find the interface
    int counter = 0;
    ptr = list;
    while(ptr)
    {
        if( ptr->state == ACTIVE )
        {
            counter += ptr->up_weight;
            if( counter > index )
            {
                return ptr;
            }
        }
        ptr = ptr->next;
    }

    ERROR_MSG("Error: random count larger than total link weights");
    return NULL;
}


struct link *handleUDP(struct link *list, struct tuple *tuple)
{
    struct hashentry *hentry = 0;
    struct link *outgoing_if = 0;

    // hack for DNS
    if( tuple->destPort == 53 )
        return getConnInterface(list);

    HASH_FIND(hh, table, tuple, sizeof(*tuple), hentry);
    if(hentry != NULL)
    {
        struct timeval current, diff;
        gettimeofday(&current, NULL);
        timersub(&current, &hentry->time, &diff);

        if(diff.tv_sec > STALE_THRESH)
        {
            //dump this entry and add a new one
            HASH_DEL(table, hentry);
            free(hentry);
            
            // assign flow to an outgoing interface
            outgoing_if = getConnInterface(list);
            if ( outgoing_if == NULL ) {
                return NULL;
            }

            hentry = (struct hashentry*)malloc(sizeof(struct hashentry));
            memcpy(&hentry->key, tuple, sizeof(hentry->key));
            gettimeofday(&hentry->time, 0);
            hentry->conn_if = outgoing_if;

            HASH_ADD(hh, table, key, sizeof(hentry->key), hentry);
            return outgoing_if;
        }
        else
        {
            //update values
            outgoing_if = hentry->conn_if;
            if(outgoing_if == NULL || outgoing_if->state != ACTIVE)
            {
                outgoing_if = getConnInterface(list);
                if ( outgoing_if == NULL ) {
                    return NULL;
                }

                hentry->conn_if = outgoing_if;
            }
            gettimeofday(&hentry->time, NULL);
            return outgoing_if;
        }
    }
    else
    {
        // assign flow an outgoing interface
        outgoing_if = getConnInterface(list);
        if ( outgoing_if == NULL ) {
            return NULL;
        }

        hentry = (struct hashentry*)malloc(sizeof(struct hashentry));
        memcpy(&hentry->key, tuple, sizeof(hentry->key));
        gettimeofday(&hentry->time, NULL);
        hentry->state = CONNECTED;
        hentry->conn_if = outgoing_if;

        HASH_ADD(hh, table, key, sizeof(hentry->key), hentry);
        return outgoing_if;
    }

    ERROR_MSG("udp unknown case");
    return NULL;
}

struct link *handleTCP(struct link *list, const struct tcphdr *tcphdr,
        struct tuple *tuple)
{
    struct hashentry *hentry = 0;
    struct link *outgoing_if = 0;

    // check if flow already exists
    HASH_FIND(hh, table, tuple, sizeof(*tuple), hentry);
    if( (hentry == NULL) && (tcphdr->syn == 1) )
    {
        // assign flow an outgoing interface
        outgoing_if = getConnInterface(list);
        if ( outgoing_if == NULL ) {
            return NULL;
        }

        // new flow
        hentry = (struct hashentry*)malloc(sizeof(struct hashentry));
        memcpy(&hentry->key, tuple, sizeof(hentry->key));
        hentry->state = CONNECTING;
        gettimeofday(&hentry->time, NULL);
        hentry->conn_if = outgoing_if;

        HASH_ADD(hh, table, key, sizeof(hentry->key), hentry);
        return outgoing_if;
    }
    else if( hentry != NULL )
    {
        //flow exists
        outgoing_if = hentry->conn_if;
        if(outgoing_if == NULL || outgoing_if->state != ACTIVE) {
            outgoing_if = getConnInterface(list);
            if ( outgoing_if == NULL ) {
                return NULL;
            }

            hentry->conn_if = outgoing_if;
        }

        if( (hentry->state == CONNECTING) && (tcphdr->ack) )
        {
            hentry->state = CONNECTED;
        }
        else if( (hentry->state == CLOSING) && (tcphdr->ack) )
        {
            hentry->state = CLOSED;
        }

        // this must be checked last
        if( (hentry->state != CLOSED) && (tcphdr->fin) )
        {
            hentry->state = CLOSING;
        }

        // clean up connection if CLOSED
        if( hentry->state == CLOSED )
        {
            HASH_DEL(table, hentry);
            free(hentry);
            hentry = 0;

            return outgoing_if;
        }
        else
        {
            // update stats
            gettimeofday(&hentry->time, NULL);
            return outgoing_if;
        }
    }
    else
    {
        // hentry = NULL and SYN = 0
        // error case...should we just add the flow?
        //hentry = (struct hashentry *)malloc(sizeof(struct hashentry));
        //memcpy(&hentry->key, &key, sizeof(struct tuple));
        //hentry->next = NULL;
        //gettimeofday(&hentry->time, NULL);
        outgoing_if = getConnInterface(list);
        return outgoing_if;
        //hentry->conn_if = outgoing_if;
        //table_add(table, hentry);
    }

    ERROR_MSG("tcp unknown case");
    return NULL;
}

static int makeFlowTuple(const struct iphdr *iphdr, int proto, 
        const void *t_hdr, struct tuple *tuple)
{
    memset(tuple, 0, sizeof(*tuple));

    if(iphdr->version == 4) {
        // Make IPv4 mapped to IPv6 addresses
        memset(tuple->destAddr.s6_addr + 10, 0xFF, 2);
        memcpy(tuple->destAddr.s6_addr + 12, &iphdr->daddr, 4);
        memset(tuple->srcAddr.s6_addr + 10, 0xFF, 2);
        memcpy(tuple->srcAddr.s6_addr + 12, &iphdr->saddr, 4);
    } else if(iphdr->version == 6) {
        const struct ip6_hdr *ip6_hdr = (const struct ip6_hdr*)iphdr;
        memcpy(&tuple->destAddr, &ip6_hdr->ip6_dst, sizeof(tuple->destAddr));
        memcpy(&tuple->srcAddr, &ip6_hdr->ip6_src, sizeof(tuple->srcAddr));
    } else {
        return FAILURE;
    }

    if(proto == IPPROTO_TCP) {
        const struct tcphdr *tcphdr = t_hdr;
        tuple->destPort = ntohs(tcphdr->dest);
        tuple->srcPort  = ntohs(tcphdr->source);
    } else if(proto == IPPROTO_UDP) {
        const struct udphdr *udphdr = t_hdr;
        tuple->destPort = ntohs(udphdr->dest);
        tuple->srcPort  = ntohs(udphdr->source);
    } else if(proto < 0) {
        return FAILURE;
    }
     
    tuple->proto = proto;

    return 0;
}

