/*
 * P P P . C
 */

#include <errno.h>
#include <signal.h>
#include <linux/if_ether.h>

#include "../common/utils.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/tunnelInterface.h"
#include "../common/contChan.h"
#include "../common/special.h"
#include "ppp.h"

static char local_buf[MAX_LINE];

static pthread_t ppp_thread;
static pthread_mutex_t ppp_mutex = PTHREAD_MUTEX_INITIALIZER;
//static int ppp_pids[MAX_INCLUDE_DEVICES];

// New model
void *pppThreadFunc(void *arg);
int pppInterfaces();
int pppInterfacesInit();

/*
 * C R E A T E  P P P  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int createPPPThread()
{
    pthread_attr_t attr;

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if( pthread_create( &ppp_thread, &attr, pppThreadFunc, NULL) )
    {
        ERROR_MSG("createPPPThread(): pthread_create failed on pppThreadFunc");
        return FAILURE;
    }
    
    pthread_attr_destroy(&attr);

    return SUCCESS;
} // End function createPPPThread()


/*
 * D E S T R O Y  P P P  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int destroyPPPThread()
{
    GENERAL_MSG("Destroying ppp thread . . . ");
    if ( pthread_join(ppp_thread, NULL) != 0 )
    {
        ERROR_MSG("pthread_join(ppp_thread) failed");
        return FAILURE;
    }

    pthread_mutex_destroy(&ppp_mutex);

    return SUCCESS;
} // End function int destroyPPPThread()


/*
 * P P P  T H R E A D  F U N C  
 *
 * Returns (void)
 *
 */
void *pppThreadFunc(void *arg)
{
    // The main thread should catch these signals.
    sigset_t new;
    sigemptyset(&new);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &new, NULL);

    connectEvdo();

    pthread_exit(NULL);

    return NULL;
} // End function void *pppThreadFuncNew()


/*
 * C O N N E C T  S P R I N T
 */
int connectSprint()
{
    int if_count = 0;
    char *curr_dev = NULL;
    FILE *dev_fh = NULL;

    if((curr_dev = strtok(getSprintData(), CONFIG_FILE_PARAM_DATA_DELIM)) != NULL)
    {
        do
        {
            char cmd[200];

            // If /dev/* doesn't exist, skip this entry.
            chomp(curr_dev);
            sprintf(cmd, "/dev/%s", curr_dev);
            if( ( dev_fh = fopen(cmd, "r") ) == NULL )
            {
                continue;
            }
            fclose(dev_fh);

            sprintf(cmd, "touch /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);


            sprintf(cmd, "echo \"/dev/%s\" > /etc/ppp/peers/sprint-%s", curr_dev, curr_dev);
            system(cmd);
            sprintf(cmd, "echo \"921600\" >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            //sprintf(cmd, "echo \"defaultroute # use cellular network for default route\" >> /etc/ppp/peers/sprint-%s", curr_dev);
            //system(cmd);
            sprintf(cmd, "echo \'debug\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'noauth\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            //sprintf(cmd, "echo \'usepeerdns # use cellular network DNS\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            //system(cmd);
            //sprintf(cmd, "echo \'connect-delay 10000\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            //system(cmd);
            sprintf(cmd, "echo \'user\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'PPP\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'persist\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'crtscts\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'lock\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'local\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'holdoff 5\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'lcp-echo-failure 4\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'lcp-echo-interval 65535\' >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \"connect '/usr/sbin/chat -v -t3 -f /etc/chatscripts/sprint-connect'\" >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \"disconnect '/usr/sbin/chat -v -t3 -f /etc/chatscripts/sprint-disconnect'\" >> /etc/ppp/peers/sprint-%s", curr_dev);
            system(cmd);

            sprintf(cmd, "pppd call sprint-%s\n", curr_dev);
            int error = system(cmd);
        
            if ( error < 0 ) 
            {
                sprintf(local_buf, "Failed to start pppd for interface %s\n", curr_dev);
                GENERAL_MSG(local_buf);
                STATS_MSG(local_buf);
            }

            if_count++;
        } while(((curr_dev = strtok(NULL, CONFIG_FILE_PARAM_DATA_DELIM)) != NULL));
    }

    return SUCCESS;
} // End function connectSprint()


/*
 * C O N N E C T  V E R I Z O N
 */
int connectVerizon()
{
    int if_count = 0;
    char *curr_dev = NULL;
    FILE *dev_fh = NULL;

    if((curr_dev = strtok(getVerizonData(), CONFIG_FILE_PARAM_DATA_DELIM)) != NULL)
    {
        do
        {
            char cmd[200];

            // If /dev/* doesn't exist, skip this entry.
            chomp(curr_dev);
            sprintf(cmd, "/dev/%s", curr_dev);
            if( ( dev_fh = fopen(cmd, "r") ) == NULL )
            {
                continue;
            }
            fclose(dev_fh);

            sprintf(cmd, "touch /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \"/dev/%s\" > /etc/ppp/peers/verizon-%s", curr_dev, curr_dev);
            system(cmd);
            sprintf(cmd, "echo \"115200\" >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'debug\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'noauth\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            //sprintf(cmd, "echo \'defaultroute\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            //system(cmd);
            //sprintf(cmd, "echo \'usepeerdns # use cellular network DNS\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            //system(cmd);
            sprintf(cmd, "echo \'connect-delay 10000\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'persist\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'user\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'show-password\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'crtscts\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'lock\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'lcp-echo-failure 4\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \'lcp-echo-interval 65535\' >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);
            sprintf(cmd, "echo \"connect '/usr/sbin/chat -v -t3 -f /etc/chatscripts/verizon-connect'\" >> /etc/ppp/peers/verizon-%s", curr_dev);
            system(cmd);

            sprintf(cmd, "pppd call verizon-%s\n", curr_dev);
            int error = system(cmd);

            if ( error < 0 ) 
            {
                sprintf(local_buf, "Failed to start pppd for interface %s\n", curr_dev);
                GENERAL_MSG(local_buf);
                STATS_MSG(local_buf);
            }

            if_count++;
        } while(((curr_dev = strtok(NULL, CONFIG_FILE_PARAM_DATA_DELIM)) != NULL));
    }

    return SUCCESS;
} // End function connectVerizon()


/*
 * C O N N E C T  E V D O
 * 
 * Returns zero on success, less than zero on failure 
 *      Success: 0
 *      Failure: -1
 *
 */
int connectEvdo()
{
    if ( getVerizonFlag() ) 
    {
        if ( connectVerizon() == FAILURE )
        {
            return FAILURE;
        }
    }

    if ( getSprintFlag() )
    {
        if ( connectSprint() == FAILURE )
        {
            return FAILURE;
        }
    }

    return SUCCESS;
} // End function int connectEvdo()
