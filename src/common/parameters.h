/*
 *  P A R A M E T E R S . H
 */

#ifndef PARAMETER_H
#define PARAMETER_H

/* This struct contains the types of algorithms that can be defined
 *
 * RR_CONN      - Round Robin Connection
 * RR_PKT       - Round Robin Per Packet
 * WRR_CONN     - Weighted Round Robin Per Connection
 * WRR_PKT      - Weighted Round Robin per Packet
 * WDRR_PKT     - Weighted Deficit Round Robin per Packet
 *
 */
enum WiProto {
	RR_CONN=1,
	RR_PKT,
	WRR_CONN,
	WRR_PKT,
	WDRR_PKT,
        WRR_PKT_v1,
        SPF
};


// Defined what type of ping to use since ICMP is blocked
// on a lot of servers/machines
enum PING_TYPE {
    UDP=1,
    ICMP
};

//Type of BandWidth test we want to use
enum BW_TYPE{
    BW_UDP=1,
    BW_TCP
};

#define BW_TYPE BW_UDP
#define BW_UDP_PKTS 20
#define BW_UDP_SLEEP 1000 //in micro secs
//#define NETWORK_CODING
#define PING_RELATIVE

// Comment this out to avoid compiling in mysql-dependent code.
#define WITH_MYSQL

// Enables measurement of RTT through exchange of timestamps in tunnel header.
// Both the wicontroller and the wigateway must support it.
//#define USE_PASSIVE_RTT

// If defined, wigateway will reboot the computer in response
// to an extended period of disconnectivity.
#define REBOOT_IF_DISCONNECTED 1

// The ping type to use (either UDP or ICMP)
#define PING_TYPE UDP

// If this is defined, compiles in code that can support either UDP or ICMP
// pings.  UDP pings are preferred, but ICMP is used in case UDP appears to be
// blocked.
//#define SUPPORT_ICMP_PING

// How often we should scan for net interfaces (deprecated, use netlink instead)
#define SCAN_INTERVAL     10
#define BURST_LOSS_THRESH 3 // 3 consecutive ping losses -> mark link INACTIVE
#define BURST_TIMEOUT     3 // In seconds
#define RTT_UPPER_BOUND   10

#define PING_LOSS_THRESH_SECS   10 // 10 seconds of ping losses -> INACTIVE

#define RTT_ACCEPTABLE 400000 //in microsecs
// Only attempt latency estimation if the inter-packet delay is reasonably
// small.  Value is in seconds.
#define LATENCY_MAX_INTER_DELAY 15

#define PING_INTERVAL      1000000 //in microseconds
#define PING_TIMEOUT       1000000 //in microseconds

#define ACTIVE_BW_BYTES		14480
#define ACTIVE_BW_INTERVAL	30000000 //in microseconds
#define ACTIVE_BW_TIMEOUT	5000000 //in microseconds
#define ACTIVE_BW_DELAY     100000 //extra 100ms delay between testing interfaces

#define MAX_BANDWIDTH 100 //should never see higher than 100 mbps
#define BANDWIDTH_EMA_WEIGHT 0.5 //weight for new measurement

#define RTT_EMA_WEIGHT 0.2 //weight for new measurement

// Bandwidth server will simply ignore any requests to send a stream larger
// than this.
#define MAX_BW_BYTES 1000000

// These settings control how often passive measurements are recorded.  Note
// that passive measurements are always taken, but reporting is delayed until
// one of these thresholds is exceeded.
#define PASSIVE_INTERVAL            1000000  //in microseconds
#define PASSIVE_TIME_THRESH         60000000 //report at least every 60 seconds
#define PASSIVE_RATECHANGE_THRESH   1.0      //report when up or down rate changes by 100%
#define PASSIVE_RATECHANGE_MIN      0.005    //rate change must be at least +/- 5kbps
#define PASSIVE_LOSS_THRESH         4        //report when at least 4 packets are lost or out-of-order

// This is used to minimize impact in cases where a socket call unexpectedly blocks.
#define FAILSAFE_SOCKET_TIMEOUT     100000

#define STATS_DUMP_INTERVAL	5000000 //in microseconds

// Time (in seconds) before considering a link inactive, ie. no packets were 
// received during this time.
#define LINK_ACTIVE_TIMEOUT     10

// Time (in seconds) before considering a gateway inactive
#define GATEWAY_ACTIVE_TIMEOUT  180

// Version String
#define VERSION .8

// Define return codes
#define SUCCESS 0
#define FAILURE -1

// Define whether we should buffer packets on the return path
#define ARE_BUFFERING

// Ports that certain channels should use
#define WIROVER_PORT        8080 // Used for main communication
#define WIROVER_PORT_STR    "8080"
#define CONTROL_PORT        8082 // Control Channel
#define CONTROL_PORT_STR    "8082"
#define TRANSFER_PORT       8083 // Transfer Channel
#define UDP_PING_PORT       8084 // Used for UDP ping traffic
#define UDP_PING_PORT_STR   "8084"
#define ACTIVE_BW_PORT	    8085 // for active bandwidth tests, TCP
#define ACTIVE_BW_PORT_STR  "8085" // for active bandwidth tests, TCP

// The size of the additional bytes that the TUNTAP struct adds to 
// a packet - the tunnel device adds it's own headers and this
// is the offset that needs to be removed from the headers
#define TUNTAP_OFFSET 4

// The MSS value to use for forwarding packets - used for port
// forwarding similar to how a regular linksys box uses port
// forwarding
#define TCP_MSS_VALUE 1400

#define SCHED_PRIORITY 10

// Deprecated
#define CONNECT_WAIT_THRESHOLD 60   // Seconds

// A MACRO to see if the Controller IP is set within the
// running code
extern int isControllerIPSet();
#define USE_CONTROLLER isControllerIPSet()

// A MACRO to see if the Controller IP is set within the
// running code
extern int isIPSecSet();
#define USE_IPSEC getIPSec()

// A MACRO to see if SSL is set in the running running code
extern int isSSLSet();
#define USE_SSL getSSL()

#ifdef GATEWAY
// The file location of resolv.conf
#define RESOLVCONF "/etc/resolv.conf"

// Default ping host to use
#define PING_HOST "www.google.com"

// How long to wait before we try to get a lease from the controller again
#define MAX_LEASE_TO 600

// Define whether we are using EVDO buffering (deprecated)
#define EVDO_BUFFERING 0
#endif

// Re-order buffer parameters
// Original values were: timeout: 80 sleep: 5 delay: 40 array_size: 1200
#define PACKET_TIMEOUT 100
#define SLEEP_TIME 5
#define MAX_DELAY  10
#define CODELEN 5
// TODO: ARRAY_SIZE should be something like (bw * delay) + (bw * sleep)
#define ARRAY_SIZE 1000

// If the sequence numbers indicate that we lost more than MAX_PACKET_LOSS
// packets, then it is more likely that the current packet arrived out of
// order.  This happens as a result of subtraction with unsigned shorts.
#define MAX_PACKET_LOSS 10000

// Deprecated
#define BATCH_SIZE 10

// Log file lcoations
//
// Log file for general output
#define LOG_FILE_LOC "wirover_log"

// Log file for statistical outpu
#define STATS_FILE_LOC "wirover_stats"

// Configuration file location - use this file to 
// configure the main parameters to the wigateway
#define CONFIG_FILE_LOC "wirover"

// This directory should contain files such as ppp0 and ppp1
#define NETWORK_NAME_PATH "/var/lib/wirover/networks"

// The watchdog file is monitored by widog
#define WATCHDOG_FILE "/var/lib/wirover/watchdog"

// Maximum length of network label
#define NETWORK_NAME_LENGTH 16

// The following parameters are use for the /etc/wirover configuration file
#define CONFIG_FILE_MAX_LINE 512
#define CONFIG_FILE_COMMENT_CHAR "#"
#define CONFIG_FILE_PARAM_LENGTH 15
#define CONFIG_FILE_PARAM_DATA_LENGTH (CONFIG_FILE_MAX_LINE - CONFIG_FILE_PARAM_LENGTH)

// Config file paramter data
#define CONFIG_FILE_PARAM_DATA_DELIM        ","
#define CONFIG_FILE_PARAM_FWD_PORTS_DELIM   "-"
#define CONFIG_FILE_PARAM_DHCP_RANGE_DELIM  "/"

// These are the TAGS in the /etc/wirover file that can
// be read in as parameters
#define CONFIG_FILE_PARAM_CONTROLLER_IP "CONTROLLER_IP"
#define CONFIG_FILE_PARAM_EXCLUDE       "EXCLUDE"
#define CONFIG_FILE_PARAM_PRIORITY      "PRIORITY"
#define CONFIG_FILE_PARAM_WEBFILTER     "WEB_FILTER"
#define CONFIG_FILE_PARAM_INTERNAL_IF   "INTERNAL_IF"
#define CONFIG_FILE_PARAM_DMZHOSTIP     "DMZHOSTIP"
#define CONFIG_FILE_PARAM_DMZHOSTPORT   "DMZHOSTPORT"
#define CONFIG_FILE_PARAM_FWD_PORTS     "FWD_PORTS"
#define CONFIG_FILE_PARAM_IPSEC         "IPSEC"
#define CONFIG_FILE_PARAM_SSL           "SSL"
#define CONFIG_FILE_PARAM_TUNNEL_IP     "TUNNEL_IP"
#define CONFIG_FILE_PARAM_ALGORITHM     "ALGORITHM"

#ifdef GATEWAY
#define CONFIG_FILE_PARAM_NOCAT         "NOCAT"
#define CONFIG_FILE_PARAM_VERIZON       "VERIZON"
#define CONFIG_FILE_PARAM_SPRINT        "SPRINT"
#define CONFIG_FILE_PARAM_HALT          "HALT"
#define CONFIG_FILE_PARAM_OPENDNS       "OPENDNS"
#endif

#ifdef CONTROLLER
#define CONFIG_FILE_PARAM_DHCP_RANGE    "DHCP_RANGE"
#endif

#define MAX_CLIENTS 255

#ifndef MAX_DEVNAME_LENGTH
#define MAX_DEVNAME_LENGTH 9
#endif

#ifndef MAX_INCLUDE_DEVICES
#define MAX_INCLUDE_DEVICES 10
#endif

#ifndef MAX_EXCLUDE_DEVICES
#define MAX_EXCLUDE_DEVICES 20
#endif

#define MAX_LINE 512
#define BUFF_MAX 255

// The highest possible MTU we calculated
#define MTU 1600
#define DEFAULT_MTU 1400

// Used for bandwidth calculations
#define DEFAULT_IP_H_SIZE 20
#define DEFAULT_TCP_H_SIZE 32

// Maximum time (in seconds) between calls to removeStaleWigateways()
#define CLEAN_GATEWAYS_INTERVAL     1

// Timeout (in seconds) the controller uses for receiving control channel
// messages
#define CONTROL_CHANNEL_TIMEOUT     5

// Deprecated
#define RADIX 10

// Newer versions of libgps use gps_stream instead of gps_query.  If compiling
// produces a warning such as "implicit declaration of function 'gps_query'",
// then comment out this define to use the deprecated function instead.
#define HAVE_GPS_STREAM 1

// Size of an IPv6 address in network format
#define IP_NETWORK_SIZE 16

// Start macro section
#define DEBUG 1
#define DEBUG_PRINT
#define GENERAL_PRINT
#define ERROR_PRINT
#define STATS_PRINT

#endif // PARAMETER_H
