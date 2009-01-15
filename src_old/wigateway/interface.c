/*
 *
 * I N T E R F A C E . C 
 *
 */

#include <arpa/inet.h>  // net to host
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <netinet/in.h> // sockaddr struct
#include <sys/file.h>


#include "../common/tunnelInterface.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/link_priority.h"
#include "../common/contChan.h"
#include "../common/udp_ping.h"
#include "../common/utils.h"
#include "../common/special.h"
#include "transfer.h"

static uint16_t      link_id = 0;


/*
 * D E M O  I N T E R F A C E  D U M P
 *
 * Returns (void)
 */
void demoInterfaceDump(struct link *head)
{
    struct link *ife;
    FILE *interface_fh;
    if( (interface_fh = fopen("/tmp/wirover_demo_interfaces.txt", "w")) == NULL )
        return;

    while( flock(fileno(interface_fh), LOCK_EX) != 0)
        usleep(50);

    fprintf(interface_fh, "\nInterface       IP Address    State  Burst RTT  Up BW (mbps)  Down BW (mbps)  Weight (up)  Weight (dn)\n");

    for(ife = head; ife; ife = ife->next)
    {
        // If needed, display the interface statistics.
        fprintf(interface_fh, "%s ", ife->ifname);
        fprintf(interface_fh, "%s ", ife->p_ip);
        fprintf(interface_fh, "%d ", ife->state);
        fprintf(interface_fh, "%d ", ife->stats.rtt);
        fprintf(interface_fh, "%f ", getLinkBandwidthUp(ife));
        fprintf(interface_fh, "%f ", getLinkBandwidthDown(ife));
        fprintf(interface_fh, "%hd ", ife->up_weight);
        fprintf(interface_fh, "%hd \n", ife->dn_weight);
    }
    flock(fileno(interface_fh), LOCK_UN);
    fclose(interface_fh);
}

/*
 * A D D  I N T E R F A C E
 *
 * Adds an interface to our valid interfaces linked list
 *
 * Returns (struct *link)
 *
 */
struct link *addInterface(char *name)
{
	struct link* ife = searchLinksByName(head_link__, name);
	if(ife) {
		// Interface is already in the list, but create a new socket for it
		close(ife->sockfd);
		if ( interfaceBind(ife, 0) < 0 )
		{
			ERROR_MSG("interfaceBind failed");
			return NULL;
		}
		else
		{
			return ife;
		}
    }

	ife = makeLink();

	strncpy(ife->ifname, name, sizeof(ife->ifname));
	ife->id = link_id++;
    ife->priority = getLinkPriority(name);

	// Create a socket and bind to this interface
    if ( interfaceBind(ife, 0) < 0 ) {
        ERROR_MSG("interfaceBind failed");
		free(ife);
        return 0;
    }

	// Get a static identifier for the network (eg. sprint, verizon)
	readNetworkName(name, ife->network, sizeof(ife->network));
	
    DEBUG_MSG("Adding interface: %s with network name: %s", name, ife->network);

	head_link__ = addLink(head_link__, ife);

    // Calculate the bandwidth using TCP
    //measureBandwidth(new);

    // Calculate the weights here, everytime an interface
    //calculateWeights();

    
	return ife;
} // End function struct interface *addInterface()

/*
 * I N T E R F A C E  C L E A N U P
 *
 * Destroy the linked list of interfaces.
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 *
 */
int interfaceCleanup(struct link *head)
{
    GENERAL_MSG("Cleaning up interface structures . . . \n");
	while(head) {
		struct link* tmp = head;
		head = head->next;

        if ( close(tmp->sockfd) < 0 )
        {
            ERROR_MSG("close failed");
        }

        free(tmp);
    }

    return SUCCESS;
} // End function int interfaceCleanup()


/*
 * I N T E R F A C E  P R I N T
 *
 * Returns (void)
 *
 */
void interfacePrint(struct link *head)
{
    struct link *ife;

    write_log("Iface\tMTU\tMet\tRX-OK\tRX-ERR\tRX-DRP\tRX-OVR\tTX-OK\tTX-ERR\tTX-DRP\tTX-OVR\tIF_UP\tRTT\n");

    for(ife = head; ife; ife = ife->next) 
    {
        // If needed, display the interface statistics.

    }
} // End function  void interfacePrint()

/*
 * I N T E R F A C E  B I N D
 *
 * Returns (int)
 *  Success: a valid socket file descriptor 
 *  Failure: -1
 *
 */
int interfaceBind(struct link *ife, int bind_port)
{
    struct sockaddr_in myAddr;
    int sockfd;

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
        ERROR_MSG("creating socket failed");
        return FAILURE;
    }

    memset(&myAddr, 0, sizeof(struct sockaddr_in));
    myAddr.sin_family      = AF_INET;
    myAddr.sin_port        = htons((unsigned short)bind_port);
    myAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(sockfd, (struct sockaddr *)&myAddr, sizeof(struct sockaddr_in)) < 0) 
    {
        ERROR_MSG("bind socket failed");
        close(sockfd);
        return FAILURE;
    }

    /*
    int on = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 )
    {
        ERROR_MSG("setsockopt SO_REUSEADDR failed");
        close(sockfd);
        return FAILURE;
    }
    */

    if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ife->ifname, IFNAMSIZ) < 0) 
    {
        ERROR_MSG("setsockopt SO_BINDTODEVICE failed");
        close(sockfd);
        return FAILURE;
    }

    ife->sockfd = sockfd;

    return sockfd;
} // End function int interfaceBind()

/*
 * S E T  D E V  D O W N  W E I G H T
 *
 * This function sets the up weight for a corresponding device
 *
 * Returns (void)
 *
 */
void setDevDownWeight(struct link *ife, float weight)
{
    ife->dn_weight = weight;
} // End function void setDevDownWeight()


/*
 * S E T  D E V  U P  W E I G H T
 *
 * This function sets the up weight for a corresponding device
 *
 * Returns (void)
 *
 */
void setDevUpWeight(struct link *ife, float weight)
{
    ife->up_weight = weight;
} // End function void setDevUpWeight()
