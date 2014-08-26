#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "configuration.h"
#include "controllers.h"
#include "debug.h"
#include "lease.h"
#include "utlist.h"

// These default values will be overwritten by read_lease_config().
static uint32_t     LEASE_BASE_SUBNET               = 0xAC100000;
static uint8_t      LEASE_CONTROLLER_SUBNET_SIZE    = 6;
static uint8_t      LEASE_GATEWAY_SUBNET_SIZE       = 14;
static int          LEASE_TIME_LIMIT                = 86400;

static struct lease* leases_head = 0;
static struct lease* leases_ip_hash = 0;
static struct lease* leases_id_hash = 0;
static struct lease** controller_leases = 0;

static void renew_lease(struct lease* lease);
static uint32_t find_controller_free_ip(int unique_id);
static uint32_t find_gw_free_ip(int unique_id, struct controller* controller);

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

    const char *lease_base_subnet = 0;
    result = config_lookup_string(config, "lease.base-subnet", &lease_base_subnet);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.range-start missing in config file");
    } else {
        inet_pton(AF_INET, lease_base_subnet, &LEASE_BASE_SUBNET);
        LEASE_BASE_SUBNET = ntohl(LEASE_BASE_SUBNET);
    }
    
    int controller_subnet_size = 0;
    result = config_lookup_int_compat(config, "lease.controller-subnet-size", &controller_subnet_size);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.subnet-size missing in config file");
    } else if(controller_subnet_size <= 0 || controller_subnet_size > UCHAR_MAX) {
        DEBUG_MSG("Invalid value for lease.subnet-size (%d)", controller_subnet_size);
    } else {
        LEASE_CONTROLLER_SUBNET_SIZE = controller_subnet_size;
    }
    controller_leases = (struct lease**)malloc(sizeof(struct lease*) * (1 << LEASE_CONTROLLER_SUBNET_SIZE));
    
    int gateway_subnet_size = 0;
    result = config_lookup_int_compat(config, "lease.gateway-subnet-size", &gateway_subnet_size);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.subnet-size missing in config file");
    } else if(gateway_subnet_size <= 0 || gateway_subnet_size > UCHAR_MAX || gateway_subnet_size + controller_subnet_size > 24) {
        DEBUG_MSG("Invalid value for lease.gateway-subnet (%d)", gateway_subnet_size);
    } else {
        LEASE_GATEWAY_SUBNET_SIZE = gateway_subnet_size;
    }

    result = config_lookup_int_compat(config, "lease.time-limit", &LEASE_TIME_LIMIT);
    if(result == CONFIG_FALSE) {
        DEBUG_MSG("lease.time-limit missing in config file");
    }

    return 0;
}

struct lease* _alloc_lease(int unique_id, uint32_t n_ip)
{
    struct lease* lease = (struct lease*)malloc(sizeof(struct lease));
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

const struct lease* grant_controller_lease(int unique_id)
{
    struct lease* lease;
    HASH_FIND(hh_uid, leases_id_hash, &unique_id, sizeof(unique_id), lease);
    if(lease) {
        renew_lease(lease);
        return lease;
    }

    uint32_t n_ip = find_controller_free_ip(unique_id);
    if(!n_ip) {
        DEBUG_MSG("Denying lease request, out of IPs");
        return 0;
    }
    return _alloc_lease(unique_id, n_ip);
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
const struct lease* grant_gw_lease(int unique_id, double latitude, double longitude)
{
    if(unique_id <= 0)
        return NULL;
    struct lease* lease;
    HASH_FIND(hh_uid, leases_id_hash, &unique_id, sizeof(unique_id), lease);
    if(lease) {
        renew_lease(lease);
        return lease;
    }
    
    struct controller* controller = assign_controller(latitude, longitude);
    if(controller == NULL){
        DEBUG_MSG("Denying lease request until there are controllers available");
        return NULL;
    }

    uint32_t n_ip = find_gw_free_ip(unique_id, controller);
    if(!n_ip) {
        DEBUG_MSG("Denying lease request, out of IPs");
        return 0;
    }
    lease = _alloc_lease(unique_id, n_ip);
    lease->controller = controller;
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

uint8_t get_gateway_subnet_size()
{
    return LEASE_GATEWAY_SUBNET_SIZE;
}
uint8_t get_controller_subnet_size()
{
    return LEASE_CONTROLLER_SUBNET_SIZE + LEASE_GATEWAY_SUBNET_SIZE;
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

static uint32_t find_controller_free_ip(int unique_id)
{
    const uint32_t max_i = (1 << LEASE_CONTROLLER_SUBNET_SIZE) - 1;
    const uint32_t subnet_mask = (1 << (LEASE_CONTROLLER_SUBNET_SIZE + LEASE_GATEWAY_SUBNET_SIZE)) - 1;
    uint32_t subnet_start = LEASE_BASE_SUBNET & (~subnet_mask);

    ipaddr_t check_ip;
    memset(&check_ip, 0, sizeof(check_ip));
    
    uint32_t h_ip;
    uint32_t n_ip;
    struct lease *lease;
    
    for(int i = 0; i < max_i; i++) {
        h_ip = subnet_start | (i << LEASE_GATEWAY_SUBNET_SIZE) | 1;
        n_ip = htonl(h_ip);
        ipv4_to_ipaddr(n_ip, &check_ip);

        HASH_FIND(hh_ip, leases_ip_hash, &check_ip, sizeof(check_ip), lease);
        if(!lease)
            return n_ip;
    }

    DEBUG_MSG("out of IP addresses");
    return 0;
}

static uint32_t find_gw_free_ip(int unique_id, struct controller* controller)
{
    static uint32_t dynamic_start = 0;
    const uint32_t broadcast_mask = (1 << LEASE_GATEWAY_SUBNET_SIZE) - 1;
    const uint32_t subnet_mask = ~broadcast_mask;

    uint32_t controller_ip;
    ipaddr_to_ipv4(&controller->priv_ip, &controller_ip);
    controller_ip = ntohl(controller_ip);

    uint32_t subnet_start = controller_ip & subnet_mask;

    ipaddr_t check_ip;
    memset(&check_ip, 0, sizeof(check_ip));

    uint32_t n_ip;
    struct lease *lease;
    
    /* We begin assigning gateway IP addresses 1 after the controller IP */
    for(dynamic_start = subnet_start + 2; (dynamic_start & broadcast_mask) < broadcast_mask; dynamic_start ++) {
        n_ip = htonl(dynamic_start);
        ipv4_to_ipaddr(n_ip, &check_ip);

        HASH_FIND(hh_ip, leases_ip_hash, &check_ip, sizeof(check_ip), lease);
        if(!lease)
            return n_ip;
    }

    DEBUG_MSG("out of IP addresses");
    return 0;
}

