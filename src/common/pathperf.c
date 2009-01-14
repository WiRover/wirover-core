#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include "configuration.h"
#include "debug.h"
#include "interface.h"
#include "ipaddr.h"
#include "netlink.h"
#include "rootchan.h"
#include "rwlock.h"
#include "utlist.h"

#ifdef CONTROLLER
#include "gateway.h"
#endif

#ifdef GATEWAY
#include "arguments.h"
#endif

static pthread_t path_perf_thread;
static int thread_running = 0;

#ifdef CONTROLLER
static void __write_path_list(FILE *file)
{
    struct gateway *gw;
    struct gateway *tmp_gw;

    ipaddr_t private_ip;
    get_private_ip(&private_ip);

    char local_node[INET6_ADDRSTRLEN];
    ipaddr_to_string(&private_ip, local_node, sizeof(local_node));
    
    const char *local_dev = get_external_interface();
    if(!local_dev)
        local_dev = "(null)";

    char local_net[NETWORK_NAME_LENGTH];
    read_network_name(local_dev, local_net, sizeof(local_net));

    char local_addr[INET6_ADDRSTRLEN] = "0.0.0.0";
    struct sockaddr_storage local_addr_tmp;
    if(get_interface_address(local_dev, (struct sockaddr *)&local_addr_tmp, 
                sizeof(local_addr_tmp)) == 0) {
        sockaddr_ntop((struct sockaddr *)&local_addr_tmp, local_addr, 
                sizeof(local_addr));
    }   

    HASH_ITER(hh_id, gateway_id_hash, gw, tmp_gw) {
        struct interface *ife;
        
        char node_addr[INET6_ADDRSTRLEN];
        ipaddr_to_string(&gw->private_ip, node_addr, sizeof(node_addr));

        DL_FOREACH(gw->head_interface, ife) {
            char remote_addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET, &ife->public_ip, remote_addr, sizeof(remote_addr));

            fprintf(file, "%-16s %-16s %-16s %-16s %-16s %-16s %-16s %-16s\n",
                    local_node, local_addr, local_dev, local_net,
                    node_addr, remote_addr, ife->name, ife->network);
        }
    }
}
#endif /* CONTROLLER */

#ifdef GATEWAY
static void __write_path_list(FILE *file)
{
    struct interface *ife;

    ipaddr_t private_ip;
    get_private_ip(&private_ip);

    char local_node[INET6_ADDRSTRLEN];
    ipaddr_to_string(&private_ip, local_node, sizeof(local_node));

    char remote_node[INET6_ADDRSTRLEN] = "0.0.0.0";
    get_controller_privip(remote_node, sizeof(remote_node));

    char remote_addr[INET6_ADDRSTRLEN] = "0.0.0.0";
    get_controller_ip(remote_addr, sizeof(remote_addr));

    obtain_read_lock(&interface_list_lock);
    DL_FOREACH(interface_list, ife) {
        char local_addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, &ife->public_ip, local_addr, sizeof(local_addr));

        fprintf(file, "%-16s %-16s %-16s %-16s %-16s %-16s %-16s %-16s\n",
                local_node, local_addr, ife->name, ife->network,
                remote_node, remote_addr, "?", "?");
    }
    release_read_lock(&interface_list_lock);
}
#endif /* GATEWAY */

/*
 * Save a list of known paths to a file for other applications to use.
 *
 * The path list is stored in /var/lib/wirover/path_list.
 */
void write_path_list()
{
    FILE *file = fopen("/var/lib/wirover/path_list", "w");
    if(file) {
        //            "xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxxxxxxxxxx\n"
        fprintf(file, "Local                                                               Remote                                                             \n");
        fprintf(file, "Node             Address          Interface        Network          Node             Address          Interface        Network         \n");
        __write_path_list(file);
        fclose(file);
    }
}

/*
 * Test whether the interface ife is the same as the one specified by name.
 *
 * Returns true in the following three cases:
 * 1. name is an IP address and matches ife's address.
 * 2. name is a string that matches ife's network.
 * 3. name is a string that matches ife's device name.
 */
int interface_matches(struct interface *ife, const char *name)
{
    struct in_addr addr;

    if(inet_pton(AF_INET, name, &addr) == 1)
        return (ife->public_ip.s_addr == addr.s_addr);

    if(strncmp(name, ife->network, sizeof(ife->network)) == 0)
        return 1;

    if(strncmp(name, ife->name, sizeof(ife->name)) == 0)
        return 1;

    return 0;
}

#ifdef CONTROLLER
static int set_pred_bw(const char *local_addr, 
        const char *remote_node, const char *remote_addr, long bandwidth)
{
    int ret = 0;

    struct gateway *gw;
    struct gateway *tmp_gw;

    ipaddr_t node_addr;
    if(remote_node)
        string_to_ipaddr(remote_node, &node_addr);

    HASH_ITER(hh_id, gateway_id_hash, gw, tmp_gw) {
        if(!remote_node || ipaddr_cmp(&node_addr, &gw->private_ip) == 0) {
            struct interface *ife;
            
            DL_FOREACH(gw->head_interface, ife) {
                if(interface_matches(ife, remote_addr)) {
                    ife->pred_bw = bandwidth;
                    ret = 1;
                    goto out;
                }
            }

            /* If remote_node was specified, then limit search to that node. */
            if(remote_node)
                break;
        }
    }

out:
    return ret;
}
#endif /* CONTROLLER */

#ifdef GATEWAY
static int set_pred_bw(const char *local_addr, 
        const char *remote_node, const char *remote_addr, long bandwidth)
{
    int ret = 0;
    struct interface *ife;

    obtain_read_lock(&interface_list_lock);
    DL_FOREACH(interface_list, ife) {
        if(interface_matches(ife, local_addr)) {
            ife->pred_bw = bandwidth;
            ret = 1;
            break;
        }
    }
    release_read_lock(&interface_list_lock);

    return ret;
}
#endif /* GATEWAY */

/*
 * Read bandwidth predictions from a file and update the relevant data
 * structures.
 *
 * Bandwidth predictions will be read from /var/lib/wirover/path_pred.
 *
 * The file must be formatted with one entry per line, where each
 * entry consists of these three values separated by spaces.
 *
 * <local interface> [<node addr>-]<remote interface> <bandwidth>
 *
 * The interfaces may be specified by IPv4 addresses, network names, or device
 * names.  Additionally, the local and remote interfaces need not be specified
 * in the same way.  Bandwidth must be specified as an integer in bits per
 * second.
 *
 * Optionally, the remote string can contain a node address to distinguish
 * interfaces that have the same name on different remote nodes.  See the
 * second example below.
 *
 * Example:
 * 10.10.10.10 1.2.3.4 500000
 * eth0 192.168.0.12-verizon 2000000
 * eth0 wlan0 25000000
 */
static void read_path_predictions()
{
    FILE *file = fopen("/var/lib/wirover/path_pred", "r");
    if(!file)
        return;

    while(!feof(file)) {
        char local_addr[16];
        char remote[32];
        long bandwidth;

        int result = fscanf(file, "%16s %32s %ld", 
                local_addr, remote, &bandwidth);
        if(result < 3)
            continue;

        const char *remote_node = NULL;
        const char *remote_addr = remote;
        int i;

        /* If the remote string contains a dash, separate it into the remote
         * node and remote addr components. */
        for(i = 0; i < sizeof(remote)-1 && remote[i]; i++) {
            if(remote[i] == '-') {
                remote_node = remote;
                remote_addr = &remote[i+1];
                remote[i] = 0;
            }
        }

        set_pred_bw(local_addr, remote_node, remote_addr, bandwidth);
    }

    fclose(file);
}

static long calc_bw_hint(const struct interface *ife)
{
    long bw_hint;

    if(ife->meas_bw > 0 && ife->pred_bw > 0) {
        double w = exp(BANDWIDTH_MEASUREMENT_DECAY * 
                (time(NULL) - ife->meas_bw_time));
        bw_hint = (long)round(w * ife->meas_bw + (1.0 - w) * ife->pred_bw);
    } else if(ife->meas_bw > 0) {
        bw_hint = ife->meas_bw;
    } else if(ife->pred_bw > 0) {
        bw_hint = ife->pred_bw;
    } else {
        bw_hint = 0;
    }

    return bw_hint;
}

#ifdef CONTROLLER
static int update_path_bandwidths()
{
    struct gateway *gw;
    struct gateway *tmp_gw;

    int count = 0;

    ipaddr_t private_ip;
    get_private_ip(&private_ip);

    char private_addr[INET6_ADDRSTRLEN];
    ipaddr_to_string(&private_ip, private_addr, sizeof(private_addr));

    HASH_ITER(hh_id, gateway_id_hash, gw, tmp_gw) {
        struct interface *ife;
        
        DL_FOREACH(gw->head_interface, ife) {
            if(ife->state == ACTIVE) {
                long hint = calc_bw_hint(ife);
                virt_remote_bandwidth_hint(ife->public_ip.s_addr, hint);
            }

            count++;
        }
    }

    return count;
}
#endif /* CONTROLLER */

#ifdef GATEWAY
static int update_path_bandwidths()
{
    struct interface *ife;
    int count = 0;

    obtain_read_lock(&interface_list_lock);
    DL_FOREACH(interface_list, ife) {
        long hint = calc_bw_hint(ife);
        count++;
    }
    release_read_lock(&interface_list_lock);

    return count;
}
#endif /* GATEWAY */

static void *path_perf_thread_fn(void *arg)
{
    while(1) {
        read_path_predictions();

        int paths = update_path_bandwidths();

        /* Adjust sleep time according to number of paths to amortize the cost
         * of the update (one system call per path). */
        int wait = 1;
        if(paths > 0)
            wait = (int)round(sqrt(paths));

        sleep(wait);
    }

    thread_running = 0;

    return NULL;
}

/*
 * Start the path performance management thread.
 *
 * The main function of this thread is to periodically update the estimated
 * bandwidth of each path in order to inform the packet routing algorithms.
 * The estimated bandwidth is computed based on recent measurements as well as
 * predictions supplied by an external source.
 */
int start_path_perf_thread()
{
    if(thread_running)
        return SUCCESS;

    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result = pthread_create(&path_perf_thread, &attr, path_perf_thread_fn, 0);
    if(result != 0) {
        ERROR_MSG("Creating thread failed");
        return FAILURE;
    }

    thread_running = 1;

    pthread_attr_destroy(&attr);
    return 0;
}

