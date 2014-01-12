/* vim: set et ts=4 sw=4:
 *
 * S C A N . C
 *
 * This file contains combines the ability to scan/rescan interfaces and
 * to continuously ping from an interface to see if we still have 
 * a connection using standard pinging tools and threads and also 
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "../common/utils.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/link_priority.h"
#include "../common/tunnelInterface.h"
#include "../common/contChan.h"
#include "../common/special.h"
#include "../common/udp_ping.h"
#include "../common/active_bw.h"
#include "../common/time_utils.h"
#include "pcapSniff.h"
#include "transfer.h"
#include "scan.h"

static char local_buf[MAX_LINE];

//static pthread_t *scan_thread = NULL;
static pthread_t scan_thread;
static pthread_mutex_t scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct timeval last_known_conn;

static int watchdog_file = -1;

int routingTableInit();


/*
 * C R E A T E  S C A N  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int createScanThread()
{
    pthread_attr_t attr;

    // If wigateway was started by widog, then this open should succeed, and we
    // must kick the watchdog regularly.  If wigateway was not started by
    // widog, then this open should fail.
    watchdog_file = open(WATCHDOG_FILE, O_WRONLY | O_NONBLOCK);
    if(watchdog_file < 0) {
        ERROR_MSG("failed to open watchdog file");
    }

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
 
    if( pthread_create( &scan_thread, &attr, scanThreadFunc, NULL) )
    {
        ERROR_MSG("createScanThread(): pthread_create failed on scanThreadFunc");
        //free(scan_thread);
        return FAILURE;
    }

    pthread_attr_destroy(&attr);

    return SUCCESS;    
} // End function createScanThread()


/*
 * D E S T R O Y  S C A N  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int destroyScanThread()
{
	//if ( &scan_thread != NULL ) 
    //{
        sprintf(local_buf, "Destroying scanning thread (%d second delay) . . . ", SCAN_INTERVAL);
        DEBUG_MSG(local_buf);
		if ( pthread_join(scan_thread, NULL) != 0 )
		{
			ERROR_MSG("main(): pthread_join(scan_thread) failed");
			return FAILURE;
		}
		//free(scan_thread);
	//}
    pthread_mutex_destroy(&scan_mutex);

    if(watchdog_file > 0) {
        close(watchdog_file);
        watchdog_file = -1;
    }

    return SUCCESS;
} // End function int destroyScanThread()

void *scanThreadFunc(void *arg)
{
    // Let another thread handle these signals
    // We don't want them to interrupt our socket calls
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &sigset, 0);

    // Initialize this to the beginning of the thread
    // execution so that we can see if no connections
    // have come up within the HALT time limit
    gettimeofday(&last_known_conn, NULL);

    if ( scanInterfacesInit() < 0 )
    {
        ERROR_MSG("interfaceScan() failed");
    }

    if ( routingTableInit() < 0 )
    {
        ERROR_MSG("routingTableInit() failed");
    }

    while ( ! getQuitFlag() )
    {
        // Every SCAN_INTERVAL, send out a ping to see
        // if our interfaces are still alive
        checkConnectivity(NULL);

        safe_usleep(SCAN_INTERVAL * 1000000);
    }

	pthread_exit(NULL);
} 



/*
 * R O U T I N G T A B L E  I N I T
 *
 * Returns (int)
 *      Success: 0
 *      Failrue: -1
 *
 */
int routingTableInit()
{
    const char *cmd = "route -n";

    FILE *route_fd = popen(cmd, "r");
    if(route_fd != NULL) {
        int line_count = 0;
        char buf[1024];
        while( fgets(buf, sizeof(buf), route_fd) )
        {
            line_count++;
            if(line_count > 2)
            {
                char dest[24], gw[24], mask[24], dev[IFNAMSIZ];

                sscanf(buf, "%23s %23s %23s %*s %*d %*d %*d %15s",
                    dest, gw, mask, dev);

                // check if route has a non-zero gw address
                if( strncmp(gw, "0.0.0.0", sizeof(gw)) != 0 )
                {
                    // for each device in the list check if gateway route matches the outgoing device
                    struct link *ife = head_link__;
                    for( ; ife; ife = ife->next )
                    {
                        if( strncmp(ife->ifname, dev, IFNAMSIZ) == 0 )
                        {
                            ife->has_gw = 1;
                            memcpy(ife->gw_ip, gw, sizeof(ife->gw_ip));
                            delRoute("0.0.0.0", "0.0.0.0", gw, dev);
                            addRoute(getControllerIP(), 0, gw, dev);
                        }
                    }
                }
            }
        }
        pclose(route_fd);
    }
    
    return SUCCESS;
}



/*
 * S C A N  I N T E R F A C E S  I N I T
 *
 * Returns (int)
 *      Success: 0
 *      Failrue: -1
 *
 */
int scanInterfacesInit()
{
    int err, rtn;
    int skfd = 0;
    FILE *dev_fd = NULL;
    char buf[512];

    struct ifreq temp;
    struct link *ife = NULL;

    // Get a socket handle so we can perform ioctl calls
    if( (skfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0 )
    {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    // Iterate through the list of interfaces
    // Get statistics - code taken from net-dev ifconfig
    if ( ! (dev_fd = fopen("/proc/net/dev", "r")))
    {
        ERROR_MSG("fopen failed");
        goto failure;
    }

    fgets(buf, sizeof buf, dev_fd);
    fgets(buf, sizeof buf, dev_fd);

    err = 0;
    while (fgets(buf, sizeof buf, dev_fd))
    {
        char name[IFNAMSIZ];
        get_name(name, buf);
        //sscanf(buf, "%*[ ]%[^:]:%*s", name);
        int priority = getLinkPriority(name);

        // Jump to next interface
        if(priority < 0) {
            //continue;
            ;
        }

        // interfaceLookup will add the interface to the list if it
        // isn't already in it
        ife = searchLinksByName(head_link__, name);
        if ( ife == NULL ) 
        {
            ife = addInterface(name);
        }

        // Copy the name into the structure
        strncpy(ife->ifname, name, IFNAMSIZ);

        // Get device's IP address 
        strncpy(temp.ifr_name, name, sizeof(temp.ifr_name));
        if(ioctl(skfd, SIOCGIFADDR, &temp) < 0)
        {
            // No IP address
            memset(ife->p_ip, 0, sizeof(ife->p_ip));
        }
        else
        {
            char p_ip[INET6_ADDRSTRLEN];
            rtn = getnameinfo(&temp.ifr_addr, sizeof(temp.ifr_addr), 
                              p_ip, sizeof(p_ip), 0, 0, NI_NUMERICHOST);
            if(rtn != 0) {
                snprintf(local_buf, sizeof(local_buf), "getnameinfo failed: %s",
                         gai_strerror(rtn));
                DEBUG_MSG(local_buf);
            }

            setLinkIp_p(ife, p_ip);

            sprintf(local_buf, "IP from setIfIpFromIfreq: %s", ife->p_ip);
            DEBUG_MSG(local_buf);
        }

        // get device netmask SIOCGIFNETMASK
        // get device broadcast SIOCGBRDADDR
        // get device ptp addr SIOCGIFDSTADDR
        // get number of devices SIOCGIFCOUNT

        // Get device MAC address
        if(ioctl(skfd, SIOCGIFHWADDR, &temp) < 0) {
            memset(ife->hwaddr, 0, sizeof(ife->hwaddr));
        } else {
            memcpy(ife->hwaddr, temp.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        // Copy in the hardware address
        ife->stats.type = temp.ifr_hwaddr.sa_family;

        // Get device flags 
        if (ioctl(skfd, SIOCGIFFLAGS, &temp) < 0)
        {
            ERROR_MSG("ioctl(SIOCGIFFLAGS) Get flags error");
        }

        // Copy in the flags
        ife->stats.flags = temp.ifr_flags;

        // Get device metric field 
        if (ioctl(skfd, SIOCGIFMETRIC, &temp) < 0)
        {
            ife->stats.metric = 0;
        }
        else
        {
            ife->stats.metric = temp.ifr_metric;
        }

        // Get device mtu value 
        if (ioctl(skfd, SIOCGIFMTU, &temp) < 0)
        {
            ife->stats.mtu = 0;
        }
        else
        {
            ife->stats.mtu = temp.ifr_mtu;
        }

        // Get device queue length
        if (ioctl(skfd, SIOCGIFTXQLEN, &temp) < 0)
        {
            ife->stats.tx_queue_len = -1; // unknown value
        }
        else
        {
            ife->stats.tx_queue_len = temp.ifr_qlen;
        }

        // Ping interface to check connectivity 
        rtn = 0;
        if( (ife->stats.flags & IFF_UP) && ife->p_ip[0] != 0 )
        {
            struct in_addr a;

            if ( ! USE_CONTROLLER ) 
            {
                struct hostent *he = gethostbyname(PING_HOST);

                if ( he )
                {
                    while(*he->h_addr_list)
                    {
                        bcopy(*he->h_addr_list++, (char *)&a, sizeof(a));
                    }

                    char pbuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &a.s_addr, pbuf, sizeof(pbuf));
                }
            }

            uint32_t dAddr = 0;
            inet_pton(AF_INET, getControllerIP(), &dAddr);
            if ( natPunch(ife, dAddr, WIROVER_PORT, WIROVER_PORT) < 0 )
            {
                DEBUG_MSG("natPunch() failed");
            }

            sprintf(local_buf, "Setting interface %s to INACTIVE until pings go through", ife->ifname);
            DEBUG_MSG(local_buf);
            ife->state = INACTIVE;
            
            // rtt will be invalid until a ping succeeds
            ife->stats.rtt = 0;

            // Set the initial last good rtt
            gettimeofday(&ife->stats.last_good_rtt, 0);
        }
    } // End while (fgets(buf, sizeof buf, dev_fd))

    fclose(dev_fd);
    close(skfd);
    return err;

failure:
    if(skfd > 0)
    {
        close(skfd);
    }

    if(dev_fd)
    {
        fclose(dev_fd);
    }

    return FAILURE;
} // End function int scanInterfacesInit()


/*
 * C H E C K  C O N N E C T I V I T Y
 *
 * Returns (void)
 *
 */
int checkConnectivity()
{
    struct link *head = head_link__;
    
    // Read HALT param from config file
    int time_until_halt = getTimeUntilHalt();
    int activeInterfaces = 0;
    int should_notify;
            
    struct timeval now;
    gettimeofday(&now, NULL);

    while(head) {
        if(head->state == ACTIVE || head->state == STANDBY) {
            struct timeval diff;
            timeval_diff(&diff, &head->stats.last_good_rtt, &now);

            if(diff.tv_sec >= PING_LOSS_THRESH_SECS) {
                enum IF_STATE old_state = setLinkState(head, INACTIVE);
                
                // Check if we need to reactivate lower priority links.
                if(old_state == ACTIVE)
                    updateSystemPriorityLevel();

                should_notify = 1;
            }
        }

        if(head->state == ACTIVE) {
            uint32_t dAddr = 0;
            inet_pton(AF_INET, getControllerIP(), &dAddr);
            if(natPunch(head, dAddr, WIROVER_PORT, WIROVER_PORT) < 0) {
                DEBUG_MSG("natPunch() failed");
            }

            activeInterfaces++;
	    }

        head = head->next;
    }
    
    // Kick the watchdog if we have at least one active interface
    if(activeInterfaces > 0 && watchdog_file >= 0) {
        write(watchdog_file, "kick", 4);
    }

    /* Send a notification if any interfaces changed state. */
    if(should_notify) {
        if (notifyController() < 0) {
            DEBUG_MSG("notifyController() failed");
        }
    }

    struct timeval curr, timeout;
    gettimeofday(&curr, NULL);
    timersub(&curr, &last_known_conn, &timeout);

    //printf("timeout: %d, %d, time_until_halt: %d\n", timeout.tv_sec, timeout.tv_usec, time_until_halt);

    if( time_until_halt > 0 && activeInterfaces <= 0 && ((int)timeout.tv_sec / 60 >= time_until_halt) )
    {
        sprintf(local_buf, "**HALTING SYSTEM AFTER %d MINUTES OF DISCONNECTIVITY**\n", time_until_halt);
        GENERAL_MSG(local_buf);
        STATS_MSG(local_buf);

        safe_usleep(1000000);

        sprintf(local_buf, "logger -t \"WiRover Version: %.2f [%d]\" No Connectivity after %d minutes, System Halt", 
            VERSION, getTimeUntilHalt(), getPid());
        system(local_buf);
        setQuitFlag(1);
        
#ifdef REBOOT_IF_DISCONNECTED
        DEBUG_MSG("Rebooting due to disconnectivity");
        system("shutdown -r now rebooting due to disconnectivity");
#endif
    }

    // for the ncurses demo display dump info to file
    demoInterfaceDump(head_link__);

    return SUCCESS;
} // End function int checkConnectivity()

/*
 * P I N G   H A N D L E R
 *
 * Callback function for pings.
 */
int pingHandler(struct ping_client_info* clientInfo, struct link* ife, struct ping_stats* stats)
{
	if(ife->stats.rtt <= 0) {
        // make sure rtt gets initialized
		ife->stats.rtt = stats->rtt;
                ife->stats.t_ul = stats->t_ul;
	} else { 
        if(stats->rtt < (ife->stats.rtt * RTT_UPPER_BOUND)) {
            // make sure the value is in a reasonable bound of the current value
		ife->stats.rtt = stats->rtt;
                ife->stats.t_ul = stats->t_ul;
       
            gettimeofday(&ife->stats.last_good_rtt, 0);
        }

        STATS_MSG("Ping over link %d (%s) rtt: %5d ms, avg_rtt: %f ms", ife->id, ife->ifname, stats->rtt/1000, ife->avg_rtt/1000);

	}

//    int pos;
//    
//    pos = sprintf(local_buf, "LINK,%lu,%d,%s,%s,%d", 
//            time(0), ife->id, ife->ifname, ife->hwaddr, ife->state);
//    if(ife->state != DEAD) {
//        pos += sprintf(local_buf+pos, ",%d,%llu,%llu,%f,%f,%d,%d",
//                ife->stats.rtt, ife->stats.bytes_sent, ife->stats.bytes_recvd,
//                getLinkBandwidthDown(ife), getLinkBandwidthUp(ife),
//                ife->packets_lost, ife->out_of_order_packets);
//    }
//    STATS_MSG(local_buf);

    // flag will be set to 1 if we should send a notify packet
    int interface_notify = 0;
   
    int curr_state = ife->state;

    updateLinkRtt(ife, stats);
    //STATS_MSG("Updated avg_rtt: %f ms", ife->avg_rtt/1000);
        STATS_MSG("t_ul: %d ms, Updated t_ul: %f ms", stats->t_ul, ife->avg_t_ul);

    if(ife->stats.rtt > 0) {
        gettimeofday(&ife->stats.last_good_rtt, NULL);
        gettimeofday(&last_known_conn, NULL);
        
        // Reset the counter -- we want to keep track of consecutive losses.
        ife->stats.num_burst_lost = 0;

        // If the current state is INACTIVE or DEAD, but the rtt > 0 then
        // send the controller notify packet.
        if ( curr_state == INACTIVE || curr_state == DEAD ) {
            DEBUG_MSG("IF %s is up (%s)", ife->ifname, ife->network);
            interface_notify = 1;    

            // Calculate new weights based off the new static bandwidth
            calculateWeights();
            
            // Pings are working, validate link, set the latency
            ife->stats.latency = (ife->stats.rtt/2);

            int systemPriorityLevel = getSystemPriorityLevel();
            if(ife->priority < systemPriorityLevel) {
                DEBUG_MSG("setting link (%s) to STANDBY (rtt > 0)", ife->ifname);
                ife->state = STANDBY;
            } else if(ife->priority == systemPriorityLevel) {
                DEBUG_MSG("setting link (%s) to ACTIVE (rtt > 0)", ife->ifname);
                ife->state = ACTIVE;
            } else {
                DEBUG_MSG("setting link (%s) to ACTIVE (rtt > 0)", ife->ifname);
                ife->state = ACTIVE;

                // The new active link has a higher priority than all currently
                // active links, so they will all be deactivated
                setSystemPriorityLevel(ife->priority);
            }
        }
    } else {
        ife->stats.num_burst_lost++;
        snprintf(local_buf, sizeof(local_buf), "Ping loss occured on %s (%s) (%d consecutive losses)",
                ife->ifname, ife->network, ife->stats.num_burst_lost);
        DEBUG_MSG(local_buf);

        // If the current state is ACTIVE, but the rtt < 0 then
        // send the controller notify packet
        if(ife->stats.num_burst_lost > BURST_LOSS_THRESH && curr_state == ACTIVE) {
            DEBUG_MSG("Burst losses have exceeded loss threshold link %s (%s)",
                    ife->ifname, ife->network);
            DEBUG_MSG("setting link %s (%s) to INACTIVE", ife->ifname, ife->network);

            ife->state = INACTIVE;
            interface_notify = 1;    

            // Reactivate links with a lower priority if there are no longer
            // any active.
            updateSystemPriorityLevel();
        }
    }
    
    if ( interface_notify == 1 ) {
        // Only notify the controller if we already have a lease (Tun device has local IP)
        if ( getTunLocalIP() != NULL ) {
            // Make sure the tunnel device is set up (which means we have a lease)
            if ( getTunPrivIP() != 0 ) {
                if ( notifyController() < 0 ) {
                    DEBUG_MSG("notifyController() failed");
                }
            }
        }
    }

    return 0;
} // end function pingHandler

/*
 * B A N D W I D T H   H A N D L E R
 *
 * Callback function for bandwidth test results.
 */
void bandwidthHandler(struct bw_client_info* bwInfo, struct link* ife, struct bw_stats* stats)
{
    updateLinkBandwidth(ife, stats->downlink_bw, stats->uplink_bw);

    computeLinkWeights(head_link__);
   
    STATS_MSG("Bandwidth for link %d (%s) down: %f mbps, up: %f mbps", stats->link_id, stats->device, stats->downlink_bw, stats->uplink_bw);
    STATS_MSG("Updated UL Bandwidth for link %d (%s): %f mbps", stats->link_id, stats->device, ife->avg_active_bw_up);
} // end function bandwidthHandler

