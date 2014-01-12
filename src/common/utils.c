/*
 * U T I L S . C 
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/pfkeyv2.h>   /* For SADB_*ALG_* */     
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "reOrderPackets.h"
#include "parameters.h"
#include "../common/debug.h"
#include "interface.h"
#include "link.h"
#include "packet_debug.h"
#include "tunnelInterface.h"
#include "contChan.h"
#include "utils.h"
#include "handleTransfer.h"
#include "link_priority.h"

#ifdef GATEWAY
#include "../wigateway/transfer.h"
#include "../wigateway/scan.h"
#include "../wigateway/pcapSniff.h"
#include "../wigateway/netlink.h"
#endif

// Variables for logging 
static pid_t pid;
static FILE *log_fh = NULL;
static FILE *stats_fh = NULL;
static int quit_flag = 0;

// Variables for config file
FILE *config_fh = NULL;

// Variables for web_filter
static char client_addresses[MAX_CLIENTS][IFNAMSIZ];
static unsigned char num_clients = 0;

static char local_buf[MAX_LINE];
static char time_buf[MAX_LINE];

// Local variables set and pulled from /etc/wirover

char verizon_data[CONFIG_FILE_PARAM_DATA_LENGTH];
char sprint_data[CONFIG_FILE_PARAM_DATA_LENGTH];
static char internal_if[CONFIG_FILE_PARAM_DATA_LENGTH];
static char controller_ip[CONFIG_FILE_PARAM_DATA_LENGTH];
static char tunnel_ip[CONFIG_FILE_PARAM_DATA_LENGTH];
#ifdef CONTROLLER
static char dhcp_range[CONFIG_FILE_PARAM_DATA_LENGTH];
#endif

static int routing_algorithm = WRR_CONN;

static int  use_opendns = 0;
static int  use_ipsec = -1;
static int  use_ssl = -1;
static int  use_verizon = 0;
static int  use_sprint = 0;

static int use_web_filter = 0;
static int use_nocat = 0;
static int use_fwd_ports = 0;

static unsigned short fwd_port_start = 0;
static unsigned short fwd_port_end = 0;

static short dmz_host_port = 0;
static uint32_t dmz_host_ip = 0;

static int time_until_halt = 0;
static sigset_t     signalSet;

void safe_usleep(unsigned int sleep_us)
{
	struct timeval sleep;
	sleep.tv_sec = sleep_us / 1000000;
	sleep.tv_usec = sleep_us % 1000000;

	int rtn = select(0, 0, 0, 0, &sleep);
	if(rtn < 0 && errno == EINTR) {
		// If this happens a lot, you may need to do something to block the
		// signal that is interrupting this.  Switch to pselect or set the
		// sigmask of the calling thread.
		DEBUG_MSG("Warning: select() was interrupted");
	}
}

/* 
 * I P T A B L E S
 */
int iptables(char *action, char *chain, char *prot, char *ip, int dport)
{
    if ( strcmp(ip, "any") == 0 ) 
    {
        sprintf(local_buf, "/sbin/iptables -%s %s -i %s -s 0/0 -d %s -p %s --dport %d -j ACCEPT", 
            action, chain, internal_if, controller_ip, prot, dport);
    }
    else
    {
        sprintf(local_buf, "/sbin/iptables -%s %s -i %s -s %s/32 -d %s -p %s --dport %d -j ACCEPT", 
            action, chain, internal_if, ip, controller_ip, prot, dport);
    }

    if ( system(local_buf) < 0 ) 
    {
        DEBUG_MSG("system() failed\n");
    }

    return SUCCESS;
} // End function int iptables()

/*
 * Add a host or network route.
 *
 * Adding a network route with address "0.0.0.0" and netmask "0.0.0.0"
 * will create a default route.
 *
 * netmask may be set to null to indicate a host route rather than a network
 * route.
 *
 * gw may be set to null to indicate no gateway.  "0.0.0.0" will not achieve
 * that; it is an error.
 */
int addRoute(const char * restrict addr, const char * restrict netmask,
        const char * restrict gw, const char * restrict device)
{
    char buffer[1024];
    int pos;

    ASSERT_OR_ELSE(addr) {
        DEBUG_MSG("Warning: parameter addr was null");
        return FAILURE;
    }

    if(netmask) {
        // Adding a network route
        pos = snprintf(buffer, sizeof(buffer), "route add -net %s netmask %s",
                addr, netmask);
    } else {
        // Adding a host route
        pos = snprintf(buffer, sizeof(buffer), "route add -host %s", addr);
    }

    if(gw) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, " gw %s", gw);
    }

    if(device) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, " dev %s", device);
    }

    printf("%s\n", buffer);

    system(buffer);
    system("ip route flush cache");
    return SUCCESS;
}

/*
 * Delete a host or network route.  Usage is the same as addRoute.
 */
int delRoute(const char * restrict addr, const char * restrict netmask,
        const char * restrict gw, const char * restrict device)
{
    char buffer[1024];
    int pos;

    ASSERT_OR_ELSE(addr) {
        DEBUG_MSG("Warning: parameter addr was null");
        return FAILURE;
    }

    if(netmask) {
        // Adding a network route
        pos = snprintf(buffer, sizeof(buffer), "route del -net %s netmask %s",
                addr, netmask);
    } else {
        // Adding a host route
        pos = snprintf(buffer, sizeof(buffer), "route del -host %s", addr);
    }

    if(gw) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, " gw %s", gw);
    }

    if(device) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, " dev %s", device);
    }
    
    printf("%s\n", buffer);

    system(buffer);
    system("ip route flush cache");
    return SUCCESS;
}

/*
 * SET SCHED PRIORITY
 *
 * Sets the process' priority.  If priority is 0, setSchedPriority will set the
 * scheduling priority to the default used by most processes.  If priority is
 * non-zero, the result will be that this process will preempt most other
 * running processes.  priority must not be negative.
 *
 * Use ps to see the effect:
 *   ps -eo command,pid,policy,rtprio,pcpu
 */
int setSchedPriority(int priority)
{
    int rtn;
    struct sched_param param;

    if(priority < 0) {
        DEBUG_MSG("Priority cannot be negative!");
        return FAILURE;
    }

    rtn = sched_getparam(0, &param);
    if(rtn < 0) {
        ERROR_MSG("sched_getparam failed");
        return FAILURE;
    }

    param.sched_priority = priority;
    const int policy = (priority == 0) ? SCHED_OTHER : SCHED_RR;

    rtn = sched_setscheduler(0, policy, &param);
    if(rtn < 0) {
        ERROR_MSG("sched_setscheduler failed");
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * D I F F
 */
struct timespec diff(struct timespec start, struct timespec end)
{
       struct timespec temp;
       if ((end.tv_nsec-start.tv_nsec)<0) {
               temp.tv_sec = end.tv_sec-start.tv_sec-1;
               temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
       } else {
               temp.tv_sec = end.tv_sec-start.tv_sec;
               temp.tv_nsec = end.tv_nsec-start.tv_nsec;
       }
       return temp;
} // End function timespec diff(timespec start, timespec end)


/*
 * G E T  O P E N  D N S
 *
 * Returns (int)
 *      Success: The PID of this process
 *      Failure: -1
 */
int getOpenDNS() 
{
    return use_opendns;
} // End function int getOpenDNS() 



/*
 * G E T  P I D
 *
 * Returns (int)
 *      Success: The PID of this process
 *      Failure: -1
 */
int getPid() 
{
   if ( (pid = getpid()) < 0 )
   {
        DEBUG_MSG("getpid() failed");
        return FAILURE;
   }
   else
   {
        return pid;
   }
} // End function int getPid() 

sigset_t *getSignalSet()
{
    return &signalSet;
}

#ifdef CONTROLLER
char *getDhcpRange()
{
    return dhcp_range;
}
#endif

char *getInternalIF()
{
    return internal_if;
}

char *getVerizonData()
{
    return verizon_data;
}

char *getSprintData()
{
    return sprint_data;
}

int getRoutingAlgorithm()
{
    return routing_algorithm;
}

char *getTunnelIP()
{
    return tunnel_ip;
}

int getNoCatFlag()
{
    return use_nocat;
}

int getDmzHostIP()
{
    return dmz_host_ip;
}

short getDmzHostPort()
{
    return dmz_host_port;    
}

int getVerizonFlag()
{
    return use_verizon;   
}

int getSprintFlag()
{
    return use_sprint;   
}

int getWebFilterFlag()
{
    return use_web_filter;
}

int getForwardPortsFlag()
{
    return use_fwd_ports;   
}

int getForwardPortStart()
{
    return fwd_port_start;
}

int getForwardPortEnd()
{
    return fwd_port_end;
}

/*
 * G E T  T I M E  U N T I L  H A L T
 *
 * Returns (static int)
 *      Success: halt time
 *      Failure: 0
 *      
 */
int getTimeUntilHalt()
{
    return time_until_halt;
} // End function int getTimeUntilHalt()

/*
 * E L A P S E D   T I M E
 *
 * Returns the difference between two timeval structs in
 * microseconds.
 */
int elapsedTime(const struct timeval* start, const struct timeval* end)
{
    int elapsed = 0;
    elapsed += (end->tv_sec - start->tv_sec) * 1000000;
    elapsed += (end->tv_usec - start->tv_usec);
    return elapsed;
}

#ifdef CONTROLLER
/*
 * P A R S E  C O N F I G  F I L E  C O N T
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int parseConfigFileCont()
{
    sprintf(local_buf, "Parsing configuration file . . . %s\n", CONFIG_FILE_LOC);
    GENERAL_MSG(local_buf);

    // Open up the config file
    if( openConfigFile() == FAILURE)
    {
        DEBUG_MSG("openConfigFile() failed");
        return FAILURE;
    }

    // Read in the internal interface
    if( readConfigFile(CONFIG_FILE_PARAM_INTERNAL_IF, internal_if) == SUCCESS )
    {
        sprintf(local_buf, "Internal interface: %s", internal_if);
        GENERAL_MSG(local_buf);
        chomp(internal_if);
    }
    else
    {
        DEBUG_MSG("Internal interface parameter not found in /etc/wirover");
        return FAILURE;
    }

    // Read in the public IP address of the controller
    if(readConfigFile(CONFIG_FILE_PARAM_CONTROLLER_IP, controller_ip) == SUCCESS)
    {
        sprintf(local_buf, "WiController IP is: %s", controller_ip);
        GENERAL_MSG(local_buf);
        chomp(controller_ip);
    }
    else
    {
        DEBUG_MSG("WiController IP parameter not found in /etc/wirover");
        return FAILURE;
    }

    // Read in the private IP for the tunnel device
    if(readConfigFile(CONFIG_FILE_PARAM_TUNNEL_IP, tunnel_ip) == SUCCESS)
    {  
        sprintf(local_buf, "WiController Private IP is: %s", tunnel_ip);
        GENERAL_MSG(local_buf);
        chomp(tunnel_ip);
    }
    else
    {
        DEBUG_MSG("Tunnel IP parameter not found in /etc/wirover");
        return FAILURE;
    }

    // Read in the DHCP range information for WiGateways
    if( readConfigFile(CONFIG_FILE_PARAM_DHCP_RANGE, dhcp_range) == SUCCESS)
    {
        sprintf(local_buf, "DHCP Range: %s", dhcp_range);
        GENERAL_MSG(local_buf);
        chomp(dhcp_range);
    }
    else
    {  
        DEBUG_MSG("DHCP Range parameter not found in /etc/wirover");
        return FAILURE;
    }

    // Set ipsec to 1 if defined in config file
    if( USE_IPSEC )
    {
        use_ipsec = 1;
        GENERAL_MSG("IPSEC Enabled\n");
    }

    // Set use_ssl to 1 if defined in config file
    if( USE_SSL )
    {
        use_ssl = 1;
        GENERAL_MSG("SSL Enabled\n");
    }

    // Set the start and end ports for bus watch forard ports
    u_int16_t start, end;
    if ( readForwardPorts(&start, &end) == SUCCESS )
    {
        sprintf(local_buf, "Forward ports enabled (%d-%d)\n", start, end);
        GENERAL_MSG(local_buf);
        setForwardPorts(start, end);
        use_fwd_ports = 1;

        // Build IPTables rules here to accept incoming packets on the Forward Ports
        char build_fwd_ports[100];
        sprintf(build_fwd_ports, "/sbin/iptables -A INPUT -s 0/0 -i %s -d %s -p udp --dport %d:%d -j ACCEPT", internal_if, controller_ip, start, end);
        system(build_fwd_ports);
        sprintf(build_fwd_ports, "/sbin/iptables -A INPUT -s 0/0 -i %s -d %s -p tcp --dport %d:%d -j ACCEPT", internal_if, controller_ip, start, end);
        system(build_fwd_ports);
    }

    fclose(config_fh); 
    return SUCCESS;
} // End function int parseConfigFileCont()
#endif


#ifdef GATEWAY
/*
 * P A R S E  C O N F I G  F I L E  G W
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int parseConfigFileGW()
{
    GENERAL_MSG("Parsing configuration file . . . %s\n", CONFIG_FILE_LOC);

    // Open up the config file
    if( openConfigFile() == FAILURE)
    {
        DEBUG_MSG("openConfigFile() failed");
        return FAILURE;
    }

    // A temporary location to store the parameter being read in
    char param_data[CONFIG_FILE_PARAM_DATA_LENGTH];

    // Read in the internal interface
    if(readConfigFile(CONFIG_FILE_PARAM_INTERNAL_IF, param_data) == FAILURE)
    {
        DEBUG_MSG("Internal interface parameter not found in /etc/wirover");
        return FAILURE;
    }

    // There may be a comma-separated list of internal interfaces, but we only
    // need the first one.
    char *first_if = strtok(param_data, ",\n\r");
    if(!first_if)
    {
        DEBUG_MSG("No internal interface specified in /etc/wirover");
        return FAILURE;
    }

    strncpy(internal_if, first_if, sizeof(internal_if));

    // Set nocat_enabled to 1 if defined in config file
    if( readConfigFile(CONFIG_FILE_PARAM_NOCAT, param_data) == SUCCESS )
    {
        use_nocat = 1;
        GENERAL_MSG("NOCAT Splashd Enabled\n");
    }

    // Set the start and end ports for DMZ host
    if ( readForwardPorts(&fwd_port_start, &fwd_port_end) == SUCCESS )
    {
        // Get DMZ host IP and destination port number.
        char param_data[CONFIG_FILE_PARAM_DATA_LENGTH];
        if( readConfigFile(CONFIG_FILE_PARAM_DMZHOSTIP, param_data) == SUCCESS )
        {
            chomp(param_data);
            dmz_host_ip = inet_addr(param_data);

            if( readConfigFile(CONFIG_FILE_PARAM_DMZHOSTPORT, param_data) == SUCCESS )
            {
                chomp(param_data);
                dmz_host_port = atoi(param_data);
                use_fwd_ports = 1;
                
                char dmz_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &dmz_host_ip, dmz_ip, sizeof(dmz_ip));

                GENERAL_MSG("Forward Ports enabled (%d-%d) to IP: %s\n", 
                        fwd_port_start, fwd_port_end, dmz_ip);
            }
        }
    }

    // Set ipsec to 1 if defined in config file
    if( USE_IPSEC )
    {
        GENERAL_MSG("IPSEC Enabled\n");
    }

    // Set use_ssl to 1 if defined in config file
    if( USE_SSL )
    {
        use_ssl = 1;
        GENERAL_MSG("SSL Enabled\n");
    }

    if( readConfigFile(CONFIG_FILE_PARAM_OPENDNS, param_data) == SUCCESS )
    {
        genResolvDotConf();
        use_opendns = 1;
        GENERAL_MSG("OPENDNS parameter found in /etc/wirover.\n");
        GENERAL_MSG("Generating /etc/resolv.conf.\n");
    }
    else
    {
        GENERAL_MSG("OPENDNS parameter not found in /etc/wirover.\n");
    }

    if(readConfigFile(CONFIG_FILE_PARAM_VERIZON, verizon_data) == SUCCESS)
    {
        use_verizon = 1;
    }

    if(readConfigFile(CONFIG_FILE_PARAM_SPRINT, sprint_data) == SUCCESS)
    {
        use_sprint = 1;
    }

    if(readLinkPriorities(config_fh) == FAILURE) {
        DEBUG_MSG("Warning: failed to read link priorities.  All links will use default priority.");
    }

    if(readConfigFile(CONFIG_FILE_PARAM_CONTROLLER_IP, controller_ip) == SUCCESS)
    {
        sprintf(local_buf, "WiController IP is: %s", controller_ip);
        GENERAL_MSG(local_buf);
    }

    chomp(controller_ip);

    if( readConfigFile(CONFIG_FILE_PARAM_HALT, param_data) == SUCCESS )
    {
        chomp(param_data);
        time_until_halt = atoi(param_data);
        sprintf(local_buf, "Halt time: (%d minutes)\n", time_until_halt);
        GENERAL_MSG(local_buf);
    }
    
    if(readConfigFile(CONFIG_FILE_PARAM_ALGORITHM, param_data) == SUCCESS) {
        // make sure it is null-terminated for safety
        param_data[sizeof(param_data)-1] = 0;
        chomp(param_data);

        if(strcasecmp(param_data, "RR_CONN") == 0)
            routing_algorithm = RR_CONN;
        else if(strcasecmp(param_data, "RR_PKT") == 0)
            routing_algorithm = RR_PKT;
        else if(strcasecmp(param_data, "WRR_CONN") == 0)
            routing_algorithm = WRR_CONN;
        else if(strcasecmp(param_data, "WRR_PKT") == 0)
            routing_algorithm = WRR_PKT;
        else if(strcasecmp(param_data, "WDRR_PKT") == 0)
            routing_algorithm = WDRR_PKT;
        else if(strcasecmp(param_data, "WRR_PKT_v1") == 0)
            routing_algorithm = WRR_PKT_v1;
        else if(strcasecmp(param_data, "SPF") == 0)
            routing_algorithm = SPF;
        else {
            DEBUG_MSG("Invalid option for parameter %s in config file: '%s'",
                    CONFIG_FILE_PARAM_ALGORITHM, param_data);
            return FAILURE;
        }
    } else {
        DEBUG_MSG("Parameter %s not found in config file, using default %d", 
                CONFIG_FILE_PARAM_ALGORITHM, routing_algorithm);
    }

    GENERAL_MSG("\n");
    fclose(config_fh); 
    return SUCCESS;
} // End function int parseConfigFileGW()

void *sigint(void *arg)
{
    int signo;

    sigwait(&signalSet, &signo);

    if(signo == SIGINT || signo == SIGTERM)
    {
        switch(signo) 
        {
            case SIGINT:
                sprintf(local_buf, "\n%s Caught SIGINT, Exiting...\n", getTime());
                GENERAL_MSG(local_buf);
                STATS_MSG(local_buf);
            break;
            case SIGTERM:
                sprintf(local_buf, "\n%s Caught SIGTERM, Exiting...\n", getTime());
                GENERAL_MSG(local_buf);
                STATS_MSG(local_buf);
            break;
        }
	}

	shutdownGateway();
    pthread_exit((void *)0);
}
#endif


/*
 * S E T  S I G  H A N D L E R S
 */
void setSigHandlers()
{
    // Catch the ctrl-c to quit program
    struct sigaction sigHandler;

    // Define the handler
#ifdef GATEWAY
    sigHandler.sa_handler = sigQuitGW;
#else
    sigHandler.sa_handler = sigQuitCont;
#endif

    // No flags, emtpy the set
    sigHandler.sa_flags   = 0;
    sigemptyset(&sigHandler.sa_mask);

    // Add whatever we signals to we want to catch
    sigaction(SIGTERM, &sigHandler, NULL);
    sigaction(SIGINT, &sigHandler, NULL);

    // Ignore SIGPIPE, which is raised by calling send() on a closed TCP
    // connection.  When SIGPIPE is ignored, send() will return -1 instead,
    // which is much more manageable.
    sigHandler.sa_handler = SIG_IGN;
    sigemptyset(&sigHandler.sa_mask);
    sigHandler.sa_flags = 0;
    sigaction(SIGPIPE, &sigHandler, 0);
} // End function void setSigHandlers()


#ifdef CONTROLLER
/*
 * S I G  Q U I T  C O N T
 */
void sigQuitCont(int signo) 
{
    switch(signo) 
    {
        case SIGINT:
            sprintf(local_buf, "\n%s Caught SIGINT, Exiting...\n", getTime());
            GENERAL_MSG(local_buf);
        break;
        case SIGTERM:
            sprintf(local_buf, "\n%s Caught SIGTERM, Exiting...\n", getTime());
            GENERAL_MSG(local_buf);
        break;
    }

    quit_flag = 1;
} // End function void sigQuitCont


/*
 * S H U T D O W N  C O N T R O L L E R
 *
 * Returns (int)
 *      Success: 0
 *      Failrue: -1
 */
int shutdownController()
{
    // Clean up - preserve the order of the shutdown
    destroyContChanThread();

#ifdef ARE_BUFFERING
        destroyReOrderThread();
#endif

    // Close the firewall to control channel traffic
    iptables("D", "INPUT", "tcp", "any", 8082);

    // Close the firewall to UDP ping traffic
    iptables("D", "INPUT", "udp", "any", 8084);

    // Iterate through the gateway list and remove any holes in the firewall
    struct wigateway *curr = getHeadGW();
    while ( curr )
    {
		struct link* link = curr->head_link;
        while ( link ) {
            iptables("D", "INPUT", "udp", link->p_ip, 8080);
            link = link->next;
        }

        curr = curr->next;
    }

    // Flush the NAT table
    system("/sbin/iptables -t nat -F");

    struct tunnel *tun = getTunnel();

    // Remove FORWARD chain rules
    sprintf(local_buf, "/sbin/iptables -D FORWARD -i %s -o %s -m state --state ESTABLISHED,RELATED,NEW -j ACCEPT", internal_if, tun->name);
    system(local_buf);
    sprintf(local_buf, "/sbin/iptables -D FORWARD -i %s -o %s -j ACCEPT", tun->name, internal_if);
    system(local_buf);

    // Remove logging
    system("/sbin/iptables -D FORWARD -j LOG --log-prefix '** WIROVER ** '");

    // Remove OUTPUT chain rule
    system("/sbin/iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP");
    system("/sbin/iptables -D OUTPUT -p tcp -m tcp --tcp-flags ACK,RST ACK,RST -j DROP");

    if ( cleanupWigateways() < 0 )
    {  
        DEBUG_MSG("wigatewayCleanup() failed");
    }

    tunnelCleanup();

    return SUCCESS;
} // End function void shutdownController()

#endif


#ifdef GATEWAY
/*
 * S I G  Q U I T  G W
 *
 * Returns (void)
 *
 */
void sigQuitGW(int signo)
{
    if(signo == SIGINT || signo == SIGTERM)
    {
        switch(signo) 
        {
            case SIGINT:
                sprintf(local_buf, "\n%s Caught SIGINT, Exiting...\n", getTime());
                GENERAL_MSG(local_buf);
            break;
            case SIGTERM:
                sprintf(local_buf, "\n%s Caught SIGTERM, Exiting...\n", getTime());
                GENERAL_MSG(local_buf);
            break;
        }

        quit_flag = 1;
     }
} // End function void sigQuitGW()


/*
 * S H U T D O W N  G A T E W A Y
 *
 * Returns (void)
 *      Success: 0
 *      Failure: -1
 */
void shutdownGateway()
{
	GENERAL_MSG("Shutting down gateway . . .\n");
    // Clean up - preserve order of shutdown

    // Tell the controller we are shutting down, only if 
    // we have an active interface
    if ( findActiveLink(head_link__) != NULL ) 
    {
        if ( USE_CONTROLLER )
        {
            if ( shutdownContChan() < 0 )
            {
                DEBUG_MSG("shutdownContChan() failed");
            }
        }
    }

/*
    // Destroy the pcap sniffing thread
    if( destroyPcapSniffThread() == FAILURE )
    {
        DEBUG_MSG("destroyPcapSniffThread() failed");
    }
*/

#ifdef ARE_BUFFERING
	// Destroy the reordering thread
	if( destroyReOrderThread() == FAILURE)
	{
		DEBUG_MSG("destroyReOrderThread() failed");
	}
#endif

    // Destroy the scan thread
    if( destroyNetLinkThread() == FAILURE )
    {
        DEBUG_MSG("destroyNetLinkThread() failed");
    }

    // Destroy the scan thread
    if( destroyScanThread() == FAILURE )
    {
        DEBUG_MSG("destroyScanThread() failed");
    }

    // Kill all instances of the pppd daemon
    // system("/usr/bin/pkill pppd");

    /* Destroy the ppp thread 
    if( destroyPPPThread() == FAILURE )
    {
        DEBUG_MSG("destroyPPPThread() failed");
    }*/

    // Clean up the interfaces
    struct link *head = head_link__;
    struct link *curr = head;

    // Replace old routing table
    while (curr)
    {
        if ( curr->has_gw )
        {
            delRoute(getControllerIP(), 0, curr->gw_ip, curr->ifname);
            addRoute("0.0.0.0", "0.0.0.0", curr->gw_ip, curr->ifname);
        }
        curr = curr->next;
    }

    // Destroy interface structures
    interfaceCleanup(head);

    // Clean up the tunnel
    tunnelCleanup(getTunnel());

    // pkill sends SIGTERM by default
    if ( getNoCatFlag() ) 
    {
        system("/usr/bin/pkill splashd");
    }


    sprintf(local_buf, "logger -t \"WiRover Version: %.2f [%d]\" Normal System Shutdown", VERSION, getPid());
    system(local_buf);

    sprintf(local_buf, "WiRover Version: %.2f PID: [%d] Normal System Shutdown\n", VERSION, getPid());
    GENERAL_MSG(local_buf);

    closeFileHandles();

    //pthread_exit(NULL);
} // End function void shutdownGateway()


/*
 * G E N  R E S O L V  D O T  C O N F
 *
 * Overwrites whatever /etc/resolv.conf is in place so that
 * we can use opendns servers which are quicker and more reliable
 *
 * Returns: (void)
 */
void genResolvDotConf()
{
    FILE* resolv_fh = fopen(RESOLVCONF, "w+");
    if(!resolv_fh) {
        DEBUG_MSG("Failed to open %s for writing", RESOLVCONF);
        return;
    }

    fprintf(resolv_fh, "# Generated by WiGateway on %s\n", getTime());
    fprintf(resolv_fh, "nameserver %s\n", "127.0.0.1"); //for dns caching with dnsmasq
    fprintf(resolv_fh, "nameserver %s\n", "208.67.222.222");
    fprintf(resolv_fh, "nameserver %s\n", "208.67.220.220");
    fclose(resolv_fh);
} // End function genResolvDotConf()
#endif


/*
 * C L O S E  F I L E  H A N D L E S
 *
 * Returns (void)
 */
void closeFileHandles()
{
    if ( log_fh != NULL )
    {
        fflush(log_fh);
        fclose(log_fh);
    }

    if ( stats_fh != NULL )
    {
        fflush(stats_fh);
        fclose(stats_fh);
    }
} // End function void closeFileHandles()


/*
 * G E T  C O N T R O L L E R  I P
 */
char *getControllerIP()
{
   return controller_ip;
} // End function char * getControllerIP()


/*
 * I S  C O N T R O L L E R  I P  S E T
 */
int isControllerIPSet()
{
    char *temp = getControllerIP();
    if( temp == NULL )
    {
        return 0;
    }
    else
    {
        return 1;
    }
} // End function int isControllerIPSet()

/*
 * G E T  S S L
 */
int getSSL()
{
   if ( use_ssl == -1 )
   {
       char param_data[CONFIG_FILE_PARAM_DATA_LENGTH];
       if(readConfigFile(CONFIG_FILE_PARAM_SSL, param_data) == FAILURE)
       {
           use_ssl = 0;
       }
       else
       {
           use_ssl = 1;
       }
   }

   return use_ssl;
} // End function int getSSL()


/*
 * G E T  I P S E C
 */
int getIPSec()
{
   if ( use_ipsec == -1 )
   {
       char param_data[CONFIG_FILE_PARAM_DATA_LENGTH];
       if(readConfigFile(CONFIG_FILE_PARAM_IPSEC, param_data) == FAILURE)
       {
           use_ipsec = 0;
       }
       else
       {
           use_ipsec = 1;
       }
   }

   return use_ipsec;
} // End function int getIPSec()


/*
 * P R I N T  I P
 *
 * A function to print out an IP address in dots and decimals given it's network format
 *
 */
void printIp(int n_ip)
{
    char ip[IFNAMSIZ];
    inet_ntop(AF_INET, &n_ip, ip, sizeof(ip));
    sprintf(local_buf, "%s", ip);
    GENERAL_MSG(local_buf);
} // End function void printIp()


/*
 * R E A D  F O R W A R D  P O R T S
 *
 * Returns (int):
 *     Success: 0
 *     Failure: -1
 *
 */
int readForwardPorts(unsigned short *start, unsigned short *end)
{
    char param_data[CONFIG_FILE_PARAM_DATA_LENGTH];

    if(readConfigFile(CONFIG_FILE_PARAM_FWD_PORTS, param_data) == FAILURE)
    {  
        GENERAL_MSG("Forward Ports parameter not found in /etc/wirover");
        GENERAL_MSG("\n");
        return FAILURE;
    }
    else
    {  
        char *curr_num = NULL;

        // Get the first number
        if((curr_num = strtok(param_data, CONFIG_FILE_PARAM_FWD_PORTS_DELIM)) != NULL)
        {  
            *start = (unsigned short)atoi(curr_num);
        }

        // Get the second number
        if((curr_num = strtok(NULL, CONFIG_FILE_PARAM_FWD_PORTS_DELIM)) != NULL)
        {  
            *end = (unsigned short)atoi(curr_num);
        }
    }

    return SUCCESS;
} // End function void readForwardPorts


/*
 * G E T  T I M E
 */
char* getTime()
{
    time_t tim=time(NULL);
    struct tm *now=localtime(&tim);
    snprintf(time_buf, sizeof(time_buf), "%d/%02d/%02d %02d:%02d:%02d", now->tm_mon+1, now->tm_mday, now->tm_year+1900, now->tm_hour, now->tm_min, now->tm_sec);
	return time_buf;
} // End function void getTime()


/*
 *
 * G E T _ N A M E
 *
 * Returns a character pointer of an interface's name
 *
 */
char *get_name(char *name, char *p)
{
    while (isspace(*p))
    {
        p++;
    }

    while (*p) 
    {
        if (isspace(*p))
            break;
        if (*p == ':') 
        {
            // Could be an alias 
            char *dot = p++;
            while (*p && isdigit(*p)) p++;
            if (*p == ':') 
            {
                // Yes it is, backup and copy it 
                p = dot;
                *name++ = *p++; 
                while (*p && isdigit(*p)) 
                {
                    *name++ = *p++; 
                }
            }
            else
            {
                // No, it isn't
                p = dot;
            }

            p++;
            break;
        }
        *name++ = *p++; 
    }

    *name = '\0'; 
    return p;
} // End function char *get_name()


/*
 * C H O M P
 */
void chomp(char *s) 
{
    while(*s && *s != '\n' && *s != '\r') s++;

    *s = 0; 
} // End function void chomp()


/*
 * W R I T E _ L O G
 *
 * Returns (void)
 *
 */
void write_log(char *text)
{
    // Print to STDOUT if DEBUG is enabled
    if ( DEBUG )
    {
        printf("%s", text);
        fflush(stdout);
    }

    if(log_fh != NULL)
    {
        fprintf(log_fh, "%s", text);
        fflush(log_fh);
    }

} // End function void write_log()



/*
 * W R I T E  S T A T S  L O G
 *
 * Returns (void)
 *
 */
void writeStatsLog(char * text)
{
    if(log_fh != NULL)
    {
        fprintf(stats_fh, "%s", text);
        fflush(stats_fh);
    }

} // End function void writeStatsLog()


/*
 * R E A D  C O N F I G  F I L E
 *
 * Searches for 'param' in file and fills in 'data' if found.
 * 
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int readConfigFile(char *param, char *data)
{
    char line[CONFIG_FILE_MAX_LINE];

    if( config_fh != NULL )
    {
        rewind(config_fh);
        while( ! feof(config_fh) )
        {
            if(fgets(line, CONFIG_FILE_MAX_LINE, config_fh) != NULL)
            {
                if ( strncmp(line, CONFIG_FILE_COMMENT_CHAR, sizeof(line)) == 0 )
                {
                    continue;
                }

                if(strncmp(param, line, strlen(param)) == 0)
                {
                    if(strncpy(data, &line[CONFIG_FILE_PARAM_LENGTH], CONFIG_FILE_PARAM_DATA_LENGTH) == NULL)
                    {
                        DEBUG_MSG("strncpy() failed");
                        return FAILURE;
                    }
                    return SUCCESS;
                }
            }
        }

        return FAILURE;
    }
    else
    {
        DEBUG_MSG("config_fh is NULL");
        return FAILURE;
    }
} // End function int readConfigFile()


/*
 * O P E N  S T A T S  L O G
 *
 * Open up the stats file so that we can log statistics to it
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int openStatsLog()
{
    // Open up the log
    if( (stats_fh = fopen(STATS_FILE_LOC, "w+")) == NULL)
    {
        return FAILURE;
    }

    return SUCCESS;
} // End function int openStatsLog()


/*
 * O P E N  L O G
 *
 * Open up the log file so that we can log statistics to it
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int openLog()
{
    // Open up the log
    if( (log_fh = fopen(LOG_FILE_LOC, "w+")) == NULL)
    {
        return FAILURE;
    }

    return SUCCESS;
} // End function int openLog()


/*
 * O P E N  C O N F I G  F I L E
 *
 * Open up the config file so that we read configuration parameters from it.
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int openConfigFile()
{
    // Open up the config file
    if( (config_fh = fopen(CONFIG_FILE_LOC, "r")) == NULL)
    {
        sprintf(local_buf, "Failed to open %s", CONFIG_FILE_LOC);
        ERROR_MSG(local_buf);
        return FAILURE;
    }

    return SUCCESS;
} // End function int openConfigFile()


/*
 * I S  C L I E N T  A L L O W E D
 *
 * If WEB_FILTER param is defined in config file, maintain list of client
 * addresses and verify that client is allowed to browse.
 *
 * Returns (int)
 *      Allowed: 1
 *      Denied: 0
 *
 */
int isClientAllowed(char *packet, int size)
{
    int i;
    int offset = 0;
    struct sockaddr_in tmpAddr;

    if( USE_CONTROLLER )
    {
        offset = 4;
    }
    else
    {
        offset = ETH_HLEN;
    }

    struct iphdr *ip_hdr = (struct iphdr *)&packet[offset];

    for(i=0; i<num_clients; i++)
    {
        inet_pton(AF_INET, client_addresses[i], &tmpAddr.sin_addr);

        if(tmpAddr.sin_addr.s_addr == ip_hdr->saddr)
        {
            return 1;
        }
    }

    return 0;
} // End function int isClientAllowed()


// Global var to indicator recv and send loops should exit
int getQuitFlag()
{
    return quit_flag;
}

// Global var to indicator recv and send loops should exit
int setQuitFlag(int value)
{
    quit_flag = value;

    return SUCCESS;
} // End function int setQuitFlag()


/*
 * U P D A T E  C S U M
 *
 * Returns (u_int16_t):
 *      Success: a checksum based on the new ip, old ip, and old checksum
 *
 */
u_int16_t updateCsum(u_int32_t newip, u_int32_t oldip, u_int16_t old_csum)
{
    //TODO: comments, and lots of them
    u_int32_t csum, oldsign, newsign;

    csum = ~old_csum;
    oldsign = csum >> 31;

    csum -= (oldip & 0xffff);
    newsign = csum >> 31;
    if(newsign != oldsign) csum -= 0x1;
    oldsign = newsign;
    csum -= (oldip >> 16);
    newsign = csum >> 31;
    if(newsign != oldsign) csum -= 0x1;
    oldsign = newsign;

    csum += (newip & 0xffff);
    newsign = csum >> 31;
    if(newsign != oldsign) csum += 0x1;
    oldsign = newsign;
    csum += (newip >> 16);
    newsign = csum >> 31;
    if(newsign != oldsign) csum += 0x1;

    // Fold 32 bits to 16 bits
    while(csum>>16)
    {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    csum = (~csum & 0xffff);

    return csum;
} // End function u_int16_t updateCsum()


/*
 * U P D A T E  C S U M  I P  P O R T
 *
 * Returns (u_int16_t) 
 *      Success: a checksum based on the new ip, old ip, and old checksum
 *
 */
u_int16_t updateCsumIPPort(u_int16_t old_csum, u_int32_t oldip, u_int16_t oldport, u_int32_t newip, u_int16_t newport)
{
	u_int32_t csum, oldsign, newsign;
	
	csum = ~old_csum;
	oldsign = csum >> 31;

	csum -= (oldip & 0xffff);
	newsign = csum >> 31;
	if(newsign != oldsign) csum -= 0x1;
	oldsign = newsign;
	csum -= (oldip >> 16);
	newsign = csum >> 31;
	if(newsign != oldsign) csum -= 0x1;
	oldsign = newsign;
	csum -= (oldport & 0xffff);
	newsign = csum >> 31;
	if(newsign != oldsign) csum -= 0x1;
	oldsign = newsign;	

	csum += (newip & 0xffff);
	newsign = csum >> 31;
	if(newsign != oldsign) csum += 0x1;
	oldsign = newsign;
	csum += (newip >> 16);
	newsign = csum >> 31;
	if(newsign != oldsign) csum += 0x1;
	oldsign = newsign;
	csum += (newport & 0xffff);
	newsign = csum >> 31;
	if(newsign != oldsign) csum += 0x1;

	// Fold 32 bits to 16 bits
    while( csum >> 16 )
    {
        csum = (csum & 0xffff) + (csum >> 16);
    }

	csum = (~csum & 0xffff);

	return csum;
} // End function u_int16_t updateCsumIPPort


/*
 * A R P _ R E Q U E S T
 *
 * ARP ioctl request.  
 * struct arpreq
 * {
 *   struct sockaddr arp_pa;             // Protocol address.
 *   struct sockaddr arp_ha;             // Hardware address.
 *   int arp_flags;                      // Flags.
 *   struct sockaddr arp_netmask;        // Netmask (only for proxy arps).
 *   char arp_dev[16];
 * }
 *
 * Returns (int)
 *  Success: 0
 *  Failure: -1
 *
 */
int arp_request(int sockfd, struct ethhdr *eth_hdr, struct iphdr *ip_hdr, char * internal_if)
{
	struct arpreq arp_req;
	struct sockaddr_in *sin = (struct sockaddr_in *) &arp_req.arp_pa;

	sin->sin_addr.s_addr = ip_hdr->daddr;
	sin->sin_family = AF_INET;

	strncpy(arp_req.arp_dev, internal_if, strlen(internal_if));

    // IOCTL ARP
    if( ioctl(sockfd, SIOCGARP, &arp_req) < 0 )
    {
        printf("arp request failed\n");
        return FAILURE;
    }
    else
    {
		memcpy(eth_hdr->h_dest, arp_req.arp_ha.sa_data, sizeof(eth_hdr->h_dest));
		/*printf("dest mac  : 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", 
					(unsigned char)eth_hdr->h_dest[0], 	
					(unsigned char)eth_hdr->h_dest[1], 
					(unsigned char)eth_hdr->h_dest[2],
					(unsigned char)eth_hdr->h_dest[3],
					(unsigned char)eth_hdr->h_dest[4],
					(unsigned char)eth_hdr->h_dest[5]);
        */
        return SUCCESS;
    }
} // End function int arp_request()


/*
 * I N T E R N A L  I F  G E T  M A C
 *
 * Returns (int):
 *   Success: 0
 *   Failure: -1
 */
char *internalIFGetMAC(struct ifreq *ifr)
{
    strncpy(ifr->ifr_name, getInternalIF(), IFNAMSIZ);

    int sockfd;

    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        ERROR_MSG("Error creating socket.");
        return NULL;
    }

    // Get internal interface MAC address
    if( ioctl(sockfd, SIOCGIFHWADDR, (char *)ifr ) < 0)
    {
        ERROR_MSG("ioctl() failed");
        return NULL;
    }
    else 
    {
        //printf("%s\n", ifr->ifr_hwaddr.sa_data);

        #ifdef GATEWAY
        setUniqueID((unsigned char *)ifr->ifr_hwaddr.sa_data);
        #endif

        /*
            ifr->ifr_hwaddr.sa_data[0], ifr->ifr_hwaddr.sa_data[1], 
            ifr->ifr_hwaddr.sa_data[2], ifr->ifr_hwaddr.sa_data[3], 
            ifr->ifr_hwaddr.sa_data[4], ifr->ifr_hwaddr.sa_data[5]);
        */

        return ifr->ifr_hwaddr.sa_data;
    }
} // End function int internalIFGetMAC


/*
 * S E T  I P  S E C
 *
 * Sets IPSEC on for a particular socket.
 *
 * Returns:
 *  Success: 0
 *  Failure: -1
 *
 */
int setIPSec(ipsec_req_t ipsr, int sockfd)
{
    // NOTE: Do this BEFORE calling connect() or accept() for TCP sockets. 
    ipsr.ipsr_ah_req = 0;
    ipsr.ipsr_esp_req = IPSEC_PREF_REQUIRED;
    ipsr.ipsr_self_encap_req = 0;
    ipsr.ipsr_auth_alg = 0;
    // TODO: Not sure which encryption algorithm to use
    // ipsr.ipsr_esp_alg = SADB_EALG_AES;
    ipsr.ipsr_esp_alg = SADB_EALG_3DESCBC;
    ipsr.ipsr_esp_auth_alg = SADB_AALG_MD5HMAC;

    if ( setsockopt(sockfd, IPPROTO_IP, IP_SEC_OPT, &ipsr, sizeof (ipsr)) == FAILURE ) {
        ERROR_MSG("setsockopt() failed");
        return FAILURE;
    }
    // You now have per-socket policy set. 

    return SUCCESS;
} // End function int setIPSec()


/*
 * O P E N  L O G S
 */
int openLogs()
{
    // Open up the log
    if( openLog() == FAILURE )
    {
        DEBUG_MSG("openLog() failed");
        return FAILURE;
    }

    // Open up the stats file
    if( openStatsLog() == FAILURE )
    {
        DEBUG_MSG("openStatsLog() failed");
        return FAILURE;
    }

    return SUCCESS;
} // End function void openLogs()


/*
 * S E T  M S S  S I Z E
 *
 * Returns: (void)
 *
 */
void setMssSize(int assigned_mss, struct tcphdr *tcp_hdr)
{
    int mss_offset = sizeof(struct tcphdr) + sizeof(short);
    int first_options_word_offset = sizeof(struct tcphdr);

    char *buf = (char *)tcp_hdr;

    unsigned short *mss = (unsigned short *)&buf[mss_offset];
    unsigned int *first_options_word = (unsigned int *)&buf[first_options_word_offset];
    unsigned int old_options = ntohl(*first_options_word);
    unsigned short new_mss = htons(assigned_mss);

    // Change maximum segment size in SYN packet to mss.
    if( (tcp_hdr->syn == 1) )
    {
        memcpy(mss, &new_mss, sizeof(new_mss));
        tcp_hdr->check = htons(updateCsum(ntohl(*first_options_word), old_options, ntohs(tcp_hdr->check)));
    }
} // End function void setMssSize

// vim: set et ts=4 sw=4 cindent:
