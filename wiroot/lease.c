#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "debug.h"
#include "lease.h"
#include "utlist.h"

// These default values will be overwritten by read_lease_config().
static const char*  LEASE_RANGE_START = "192.168.1.1";
static const char*  LEASE_RANGE_END   = "192.168.1.254";
static int          LEASE_TIME_LIMIT = 86400;

static struct lease* leases_head = 0;
static struct lease* leases_ip_hash = 0;
static struct lease* leases_hw_hash = 0;

static char msg_buffer[1024];

static void renew_lease(struct lease* lease);
static uint32_t find_free_ip();

/*
 * READ LEASE CONFIG
 *
 * Reads from the config file those entries pertaining to leases.
 */
int read_lease_config(const config_t* config)
{
    int result;

    ASSERT_OR_ELSE(config) {
        return -1;
    }

    result = config_lookup_string(config, "lease.range-start", &LEASE_RANGE_START);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.range-start missing in config file");
    }
    
    result = config_lookup_string(config, "lease.range-end", &LEASE_RANGE_END);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.range-end missing in config file");
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
const struct lease* grant_lease(const uint8_t* hw_addr, unsigned int hw_addr_len)
{
    struct lease* lease;

    HASH_FIND(hh_hw, leases_hw_hash, hw_addr, hw_addr_len, lease);
    if(lease) {
        renew_lease(lease);
        return lease;
    }

    uint32_t n_ip = find_free_ip();
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
    memcpy(lease->hw_addr, hw_addr, sizeof(lease->hw_addr));
    lease->ip = n_ip;
    lease->end = time(&lease->start) + LEASE_TIME_LIMIT;

    DL_APPEND(leases_head, lease);
    HASH_ADD(hh_ip, leases_ip_hash, ip, sizeof(lease->ip), lease);
    HASH_ADD(hh_hw, leases_hw_hash, hw_addr, sizeof(lease->hw_addr), lease);

    char p_ip[INET_ADDRSTRLEN];
    char p_hw_addr[100];
    inet_ntop(AF_INET, &n_ip, p_ip, sizeof(p_ip));
    to_hex_string((const char*)hw_addr, hw_addr_len, p_hw_addr, sizeof(p_hw_addr));

    snprintf(msg_buffer, sizeof(msg_buffer),
             "Granted lease of %s for hw_addr %s",
             p_ip, p_hw_addr);
    DEBUG_MSG(msg_buffer);

    return lease;
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

    char p_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &lease->ip, p_ip, sizeof(p_ip));

    char p_hw_addr[100];
    to_hex_string((const char*)lease->hw_addr, sizeof(lease->hw_addr), p_hw_addr, sizeof(p_hw_addr));

    snprintf(msg_buffer, sizeof(msg_buffer),
             "Renewing lease of %s for hw_addr %s",
             p_ip, p_hw_addr);
    DEBUG_MSG(msg_buffer);

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
static uint32_t find_free_ip()
{
    // next IP to try, in host byte order
    static uint32_t h_next_ip = 0;

    uint32_t start = 0;
    uint32_t end = 0;

    inet_pton(AF_INET, LEASE_RANGE_START, &start);
    start = ntohl(start);

    inet_pton(AF_INET, LEASE_RANGE_END, &end);
    end = ntohl(end);

    // This is the case when find_free_ip() is called for the first time or if
    // the lease ranges are ever changed.
    if(h_next_ip < start || h_next_ip > end) {
        h_next_ip = start;
    }

    // We will give up if we return to this IP after trying all the rest
    uint32_t first_ip_tried = h_next_ip;

    do {
        uint32_t n_curr_ip = htonl(h_next_ip);
        
        h_next_ip++;
        if(h_next_ip > end) {
            h_next_ip = start;
        }

        struct lease* lease;
        HASH_FIND(hh_ip, leases_ip_hash, &n_curr_ip, sizeof(n_curr_ip), lease);
        if(!lease) {
            return n_curr_ip;
        }
    } while(h_next_ip != first_ip_tried);

    return 0;
}

