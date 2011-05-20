#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "debug.h"
#include "lease.h"
#include "utlist.h"

#define BROADCAST_MASK  0x000000FF

// These default values will be overwritten by read_lease_config().
static uint32_t     LEASE_RANGE_START   = 0xC0A80000;
static uint32_t     LEASE_RANGE_END     = 0xC0A8FFFF;
static uint32_t     LEASE_NETMASK       = 0xFFFF0000;
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

    const char *lease_range_start = 0;
    result = config_lookup_string(config, "lease.range-start", &lease_range_start);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.range-start missing in config file");
    } else {
        inet_pton(AF_INET, lease_range_start, &LEASE_RANGE_START);
        LEASE_RANGE_START = ntohl(LEASE_RANGE_START);
    }
    
    const char *lease_range_end = 0;
    result = config_lookup_string(config, "lease.range-end", &lease_range_end);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.range-end missing in config file");
    } else {
        inet_pton(AF_INET, lease_range_end, &LEASE_RANGE_END);
        LEASE_RANGE_END = ntohl(LEASE_RANGE_END);
    }
    
    const char *lease_netmask = 0;
    result = config_lookup_string(config, "lease.netmask", &lease_netmask);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.netmask missing in config file");
    } else {
        inet_pton(AF_INET, lease_netmask, &LEASE_NETMASK);
        LEASE_NETMASK = ntohl(LEASE_NETMASK);
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
 * Finds a free IP address in the lease range.  Usually this will return
 * a static IP based on the unique_id.  If this is not possible, we will
 * search for a free IP starting from the end of the range.
 *
 * In most cases, this will return after one lookup.  Even in the worst case,
 * when the entire range is in use, this will likely take a fraction of a
 * millisecond on a modern machine.
 *
 * Returns an IP in network byte order or 0 if one is unavailable.
 */
static uint32_t find_free_ip(int unique_id)
{
    static uint32_t dynamic_start = 0;

    /* First try making an IP address out of the unique ID.
     * Bit shift by one to avoid assigning a .255 address. */
    uint32_t next_ip = LEASE_RANGE_START + (unique_id << 1);
    uint32_t n_ip = htonl(next_ip);

    struct lease *lease;
    if(next_ip >= LEASE_RANGE_START && next_ip <= LEASE_RANGE_END) {
        HASH_FIND(hh_ip, leases_ip_hash, &n_ip, sizeof(n_ip), lease);
        if(!lease)
            return n_ip;
    }

    if(dynamic_start < LEASE_RANGE_START || dynamic_start > LEASE_RANGE_END) {
        dynamic_start = LEASE_RANGE_END;
       
        // Avoid assigning a broadcast address.
        if((dynamic_start & BROADCAST_MASK) == BROADCAST_MASK)
            dynamic_start--;
    }

    while(dynamic_start > LEASE_RANGE_START) {
        n_ip = htonl(dynamic_start);

        HASH_FIND(hh_ip, leases_ip_hash, &n_ip, sizeof(n_ip), lease);
        if(!lease)
            return n_ip;

        dynamic_start--;

        // Avoid assigning a broadcast address.
        if((dynamic_start & BROADCAST_MASK) == BROADCAST_MASK)
            dynamic_start--;
    }

    DEBUG_MSG("out of IP addresses");
    return 0;
}

