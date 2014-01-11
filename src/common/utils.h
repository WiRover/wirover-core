/*
 * U T I L S . H
 */

#ifndef UTILS_H
#define UTILS_H

#include "uthash.h"
// Crap required for utils.h
#include <pthread.h>
#include <sys/time.h>

# if 0
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif
#include "parameters.h"



#ifndef MIN
#define MIN(a,b) ((a > b) ? b : a)
#endif

pthread_mutex_t exit_mutex;
pthread_cond_t exit_cond;

int setSchedPriority(int priority);

struct timespec diff(struct timespec start, struct timespec end);
sigset_t *getSignalSet();
void *sigint(void *arg);
void setSigHandlers();
void chomp(char *s);
void genResolvDotConf();
void closeFileHandles();
void freeControllerIP();
void safe_usleep(unsigned int sleep_us);

int readForwardPorts(unsigned short *start, unsigned short *end);
char* getTime();
char *get_name(char *name, char *p);

int iptables(char *action, char *chain, char *prot, char *ip, int dport);
int addRoute(const char * restrict addr, const char * restrict netmask,
        const char * restrict gw, const char * restrict device);
int delRoute(const char * restrict addr, const char * restrict netmask,
        const char * restrict gw, const char * restrict device);
int getPid();
int getOpenDNS();
int parseConfigFileGW();
int parseConfigFileCont();
int openLogs();
int openLog();
int openStatsLog();

void printIp(int n_ip);

void write_log(char * text);
void writeStatsLog(char * text);

int readConfigFile(char * param, char * data);
int openConfigFile();

int openRunFile();
int isClientAllowed(char *buffer, int bufSize);

int getQuitFlag();
int setQuitFlag(int value);


char *getTunnelIP();
char *getInternalIF();
char *getControllerIP();
char *getExcludeDevice(int index);
char *getVerizonData();
char *getSprintData();
int  getRoutingAlgorithm();

#ifdef CONTROLLER
char *getDhcpRange();
int shutdownController();
#endif

int isControllerIPSet();

#ifdef GATEWAY
void shutdownGateway();
#endif

int getNumExcludeDevices();
int getNoCatFlag();
int getDmzHostIP();
short getDmzHostPort();
int getIPSec();
int getSSL();
int getVerizonFlag();
int getSprintFlag();
int getWebFilterFlag();
int getForwardPortsFlag();
int getForwardPortStart();
int getForwardPortEnd();
int getTimeUntilHalt();

int elapsedTime(const struct timeval* start, const struct timeval* end);

// Interrupt handlers
void sigQuitGW(int signo);
void sigQuitCont(int signo);

uint16_t updateCsum(uint32_t newip, uint32_t oldip, uint16_t old_csum);
uint16_t updateCsumIPPort(uint16_t old_csum, uint32_t oldip, uint16_t oldport, uint32_t newip, uint16_t newport);

struct ethhdr;
struct iphdr;
struct internal_if;
struct ifreq;
struct tcphdr;

int arp_request(int sockfd, struct ethhdr *eth_hdr, struct iphdr *ip_hdr, char *internal_if);
char *internalIFGetMAC(struct ifreq *ifr);
void setMssSize(int mss, struct tcphdr *tcp_hdr);

/*
 * Different preferences that can be requested from IPSEC protocols.
 */
#define IP_SEC_OPT              0x22    /* Used to set IPSEC options */
#define IPSEC_PREF_NEVER        0x01
#define IPSEC_PREF_REQUIRED     0x02
#define IPSEC_PREF_UNIQUE       0x04
/*
 * This can be used with the setsockopt() call to set per socket security
 * options. When the application uses per-socket API, we will reflect
 * the request on both outbound and inbound packets.
 */

typedef struct ipsec_req {
    uint32_t        ipsr_ah_req;            /* AH request */
    uint32_t        ipsr_esp_req;           /* ESP request */
    uint32_t        ipsr_self_encap_req;    /* Self-Encap request */
    uint8_t         ipsr_auth_alg;          /* Auth algs for AH */
    uint8_t         ipsr_esp_alg;           /* Encr algs for ESP */
    uint8_t         ipsr_esp_auth_alg;      /* Auth algs for ESP */
} ipsec_req_t;

int setIPSec(ipsec_req_t ipsr, int sockfd);

#endif
