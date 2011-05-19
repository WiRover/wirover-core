#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "debug.h"
#include "lease.h"
#include "utlist.h"

// These default values will be overwritten by read_lease_config().
static const char   *LEASE_RANGE_START  = "192.168.0.0";
static const char   *LEASE_RANGE_END    = "192.168.255.255";
static int          GATEWAY_SUBNET_SIZE = 32;
static int          LEASE_TIME_LIMIT    = 86400;

static struct lease* leases_head = 0;
static struct lease* leases_ip_hash = 0;
static struct lease* leases_id_hash = 0;

static void renew_lease(struct lease* lease);
static uint32_t find_free_ip(int unique_id);

/*
 * READ LEASE CONFIG
 *
 * Reads from the config file those entries pertaining to leases.
 */
int read_lease_config(const config_t* config)
{
    int result;

    // Just use default values if config file was not found.
    if(!config) {
        return 0;
    }

    result = config_lookup_string(config, "lease.range-start", &LEASE_RANGE_START);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.range-start missing in config file");
    }
    
    result = config_lookup_string(config, "lease.range-end", &LEASE_RANGE_END);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.range-end missing in config file");
    }

    int subnet_size;
    result = config_lookup_int(config, "lease.gateway-subnet-size", &subnet_size);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.gateway-subnet-size missing in config file");
    } else if(subnet_size < 0 || subnet_size > IPV4_ADDRESS_BITS) {
        DEBUG_MSG("lease.gateway-subnet-size has invalid value (%d)", subnet_size);
    } else {
        GATEWAY_SUBNET_SIZE = subnet_size;
    }
    
    result = config_lookup_int(config, "lease.time-limit", &LEASE_TIME_LIMIT);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.time-limit missing in config file");
    }

    return 0;
}

/*
 * GRANT LEASE
 *
 * Grants a new lease for the hardware address or renews an old one if one
 * exists for the hardware address.
 *
 * Returns a lease on success.  The memory for this lease is managed by the
 * lease module and must not be freed by the caller.  Returns a null pointer if
 * a lease cannot be granted.
 */
const struct lease* grant_lease(int unique_id)
{
    struct lease* lease;

    HASH_FIND(hh_uid, leases_id_hash, &unique_id, sizeof(unique_id), lease);
    if(lease) {
        renew_lease(lease);
        return lease;
    }

    uint32_t n_ip = find_free_ip(unique_id);
    if(!n_ip) {
        DEBUG_MSG("Denying lease request, out of IPs");
        return 0;
    }

    lease = (struct lease*)malloc(sizeof(struct lease));
    ASSERT_OR_ELSE(lease) {
        DEBUG_MSG("out of memory");
        return 0;
    }

    memset(lease, 0, sizeof(struct lease));
    lease->unique_id = unique_id;
    ipv4_to_ipaddr(n_ip, &lease->ip);
    lease->end = time(&lease->start) + LEASE_TIME_LIMIT;

    DL_APPEND(leases_head, lease);
    HASH_ADD(hh_ip, leases_ip_hash, ip, sizeof(lease->ip), lease);
    HASH_ADD(hh_uid, leases_id_hash, unique_id, sizeof(lease->unique_id), lease);

    char p_ip[INET6_ADDRSTRLEN];
    ipaddr_to_string(&lease->ip, p_ip, sizeof(p_ip));

    DEBUG_MSG("Granted lease of %s for node %d", p_ip, unique_id);

    return lease;
}

/*
 * REMOVE STALE LEASES
 */
void remove_stale_leases()
{
    time_t now = time(0);

    struct lease* lease;
    struct lease* tmp;
    DL_FOREACH_SAFE(leases_head, lease, tmp) {
        if(now >= lease->end) {
            DL_DELETE(leases_head, lease);
            HASH_DELETE(hh_ip, leases_ip_hash, lease);
            HASH_DELETE(hh_uid, leases_id_hash, lease);

            char p_ip[INET6_ADDRSTRLEN];
            ipaddr_to_string(&lease->ip, p_ip, sizeof(p_ip));

            DEBUG_MSG("Expired lease of %s for node %d", p_ip, lease->unique_id);

            free(lease);
        }
    }
}

/*
 * RENEW LEASE
 *
 * Renews a lease by updated its start and end times.
 */
static void renew_lease(struct lease* lease)
{
    ASSERT_OR_ELSE(lease) {
        return;
    }

    char p_ip[INET6_ADDRSTRLEN];
    ipaddr_to_string(&lease->ip, p_ip, sizeof(p_ip));

    DEBUG_MSG("Renewed lease of %s for node %d", p_ip, lease->unique_id);

    lease->end = time(&lease->start) + LEASE_TIME_LIMIT;
}

/*
 * FIND FREE IP
 *
 * In most cases, this will return after one lookup.  Even in the worst case,
 * when the entire range is in use, this will likely take a fraction of a
 * millisecond on a modern machine.
 *
 * Returns an IP in network byte order or 0 if one is unavailable.
 */
static uint32_t find_free_ip(int unique_id)
{
    uint32_t start = 0;
    uint32_t end = 0;

    inet_pton(AF_INET, LEASE_RANGE_START, &start);
    //start = ntohl(start) >> (IPV4_ADDRESS_BITS - GATEWAY_SUBNET_SIZE);
    start = ntohl(start);

    inet_pton(AF_INET, LEASE_RANGE_END, &end);
    //end = ntohl(end) >> (IPV4_ADDRESS_BITS - GATEWAY_SUBNET_SIZE);
    end = ntohl(end);

    uint32_t next_ip = start + unique_id;
    if(next_ip < start || next_ip > end) {
        next_ip = start;
    }

    // We will give up if we return to this IP after trying all the rest
    uint32_t first_ip_tried = next_ip;

    do {
        //uint32_t n_curr_ip = htonl(next_ip << 
        //        (IPV4_ADDRESS_BITS - GATEWAY_SUBNET_SIZE));
        uint32_t n_curr_ip = htonl(next_ip);
        
        next_ip++;
        if(next_ip > end) {
            next_ip = start;
        }

        struct lease* lease;
        HASH_FIND(hh_ip, leases_ip_hash, &n_curr_ip, sizeof(n_curr_ip), lease);
        if(!lease) {
            return n_curr_ip;
        }
    } while(next_ip != first_ip_tried);

    return 0;
}

