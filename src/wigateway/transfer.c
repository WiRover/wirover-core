/*
 * T R A N S F E R . C
 */

#include <arpa/inet.h>  // net to host
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <net/route.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>

#include "../common/utils.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/link.h"
#include "../common/tunnelInterface.h"
#include "../common/contChan.h"
#include "../common/special.h"
#include "../common/handleTransfer.h"
#include "pcapSniff.h"
//#include "pingInterface.h"
#include "transfer.h"

static char local_buf[MAX_LINE];

static pthread_t transfer_thread;
static pthread_mutex_t transfer_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int alarm_count;

// New model
void *transferThreadFunc(void *arg);


/*
 * M E A S U R E  B A N D W I D T H
 *
 * Returns (int)
 *      Success: 0
 *      Failure: -1
 */
int measureBandwidth(struct interface *curr)
{   
    if (curr != NULL)
    {   
        if ( curr->state != DEAD && curr->n_ip != 0)
        {   
            int trans_sockfd;
            if( (trans_sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
            {   
                ERROR_MSG("socket() failed");
                return FAILURE;
            }

            int on = 1;
            if ( setsockopt(trans_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0 )
            {   
                ERROR_MSG("setsockopt(SO_REUSEADDR) failed");
                return FAILURE;
            }

            if(setsockopt(trans_sockfd, SOL_SOCKET, SO_BINDTODEVICE, curr->name, IFNAMSIZ) < 0)
            {   
                ERROR_MSG("setsockopt SO_BINDTODEVICE failed");
                close(trans_sockfd);
                return FAILURE;
            }

            struct sockaddr_in trans_dest;
            trans_dest.sin_family = PF_INET;
            trans_dest.sin_port   = htons(TRANSFER_PORT);
            inet_pton(PF_INET, getControllerIP(), &trans_dest.sin_addr);


            // TODO: Get rid of hack
            // Add a special route to the controller just to set up communication
            addRoute(getControllerIP(), "255.255.255.255", curr->name);

            int rtn = connect(trans_sockfd, (struct sockaddr *)&trans_dest, sizeof(trans_dest));
            if(rtn < 0) {
                close(trans_sockfd);
                ERROR_MSG("connect() failed");
                return FAILURE;
            }
            else
            {
                sprintf(local_buf, "Connected to : %s:%d, using ife: %s\n", getControllerIP(), TRANSFER_PORT, curr->name);
                GENERAL_MSG(local_buf);
                curr->trans_sockfd = trans_sockfd;
            }

            curr->stats.static_uplink_bw = sendFile(trans_sockfd);
            curr->stats.static_downlink_bw = recvFile(trans_sockfd);

            // copy to dynamic stats too
            curr->stats.uplink_bw = curr->stats.static_uplink_bw;
            curr->stats.downlink_bw = curr->stats.static_downlink_bw;

            sprintf(local_buf, "Static downlink_bw (%s): %f", curr->name, curr->stats.static_downlink_bw);
            STATS_MSG(local_buf);

            sprintf(local_buf, "Static uplink_bw (%s): %f", curr->name, curr->stats.static_uplink_bw);
            STATS_MSG(local_buf);

            //delRoute(getControllerIP(), "255.255.255.255", curr->name);
        }

        curr = curr->next;
    } // End if(curr != NULL)

    return SUCCESS;
} // End function measureBandwidth()



/*
 * C A T C H  A L A R M
 */
void catchAlarm(int sig)
{
    // This is where we should see if our links are being utilized,
    // if not, then opportunistically do a BW transfer on the links
    // to measure the link
    if ( getQuitFlag() ) 
    {
        return;
    }
    
    // Get a list of the interfaces
    struct link *ife = head_link__;
    while ( ife ) 
    {
        // Make sure we only do tests if the link is ACTIVE, also
        // make sure we don't initiate a test if there is one in progress already
        if ( ife->state != ACTIVE && ife->stats.transfer_in_progress == 0 )
        {
            ife = ife->next;
            continue;
        }

		DEBUG_MSG("would have called measureBandwidth()");
        // Perform BW transfer, and estimate bandwidth
//        if ( measureBandwidth(ife) < 0 )
//        {
//            DEBUG_MSG("measureBandwidth() failed");
//            return;
//        }

        ife = ife->next;
    } // End while( ife )
} // End function void catchAlarm(int sig)


/*
 * C R E A T E  T R A N S F E R  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int createTransferThread()
{
    pthread_attr_t attr;

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if( pthread_create( &transfer_thread, &attr, transferThreadFunc, NULL) )
    {
        ERROR_MSG("createTransferThread(): pthread_create failed on transferThreadFunc");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);

    return SUCCESS;
} // End function createTransferThread()


/*
 * D E S T R O Y  T R A N S F E R  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int destroyTransferThread()
{ 
    if ( &transfer_thread != NULL ) 
    {
        GENERAL_MSG("Destroying transfer thread . . . ");
        if ( pthread_join(transfer_thread, NULL) != 0 )
        {
            ERROR_MSG("pthread_join(transfer_thread) failed");
            return FAILURE;
        }
    }

    pthread_mutex_destroy(&transfer_mutex);
    return SUCCESS;
} // End function int destroyTransferThread()


/*
 * T R A N S F E R  T H R E A D  F U N C  
 *
 * Returns (void)
 *
 */
void *transferThreadFunc(void *arg)
{
    alarm_count = 1;

    // The main thread should catch these signals.
    sigset_t new;
    sigemptyset(&new);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &new, NULL);

    struct itimerval value;
    struct sigaction sact;

    sigemptyset(&sact.sa_mask);

    // The catchAlarm function should catch the alarm
    sact.sa_flags = 0;
    sact.sa_handler = catchAlarm;
    sigaction(SIGALRM, &sact, NULL);

    value.it_interval.tv_sec = BW_PERIOD;
    value.it_interval.tv_usec = 0;
    value.it_value.tv_sec = BW_PERIOD;
    value.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &value, 0);

    createTransFile(); 

    while( ! getQuitFlag() ) 
    {
        // The alarm should go off every BW_PERIOD seconds
        safe_usleep(BW_PERIOD * 1000000);
    }

    closeTransFile();
	pthread_exit(NULL);
} // End function void *transferThreadFuncNew()
