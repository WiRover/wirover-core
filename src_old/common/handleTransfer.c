/*
 * T R A N S F E R . C
 */

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "../common/utils.h"
#include "../common/parameters.h"
#include "../common/debug.h"
#include "../common/interface.h"
#include "../common/tunnelInterface.h"
#include "../common/contChan.h"
#include "../common/special.h"
#include "handleTransfer.h"

//static char local_buf[MAX_LINE];

static pthread_t handle_transfer_thread;
static pthread_mutex_t handle_transfer_mutex = PTHREAD_MUTEX_INITIALIZER;

static FILE *trans_file = NULL;

// New model
void *handleTransferThreadFunc(void *arg);


/*
 * C A L C U L A T E  B A N D W I D T H 
 *
 * @param time: the time in seconds
 *
 * Returns (float)
 *      Success: The bandwidth of an interface as a float in mbps
 *      Failure: -1
 */
float calculateBandwidth(int filesize, float time)
{
    //printf("Calculating Bandwidth using bits: %d  time: %f\n", (filesize * 8), time);
    float bw = 0;

    // Convert filesize to bits
    filesize = filesize * 8;

    // Do calculation
    // Should be in bits per second (bps)
    bw = (float)filesize / time;

    // Convert to bits per microsecond (mbps)
    bw = bw / 1000000;

    return bw;
} // End function float calculateBandwidth()


/*
 * C R E A T E  T R A N S  F I L E
 */
FILE *createTransFile()
{
    trans_file = fopen(TRANS_FILE_NAME, "w+");
    if(!trans_file) {
        ERROR_MSG("fopen() failed");
        return NULL;
    }

    char buffer[1000];
    memset(buffer, 0, sizeof(buffer));

    int bytes_written = 0;
    while ( bytes_written < TRANS_FILE_SIZE ) {
        int result = fwrite(buffer, 1, sizeof(buffer), trans_file);
        if(result < 0) {
            ERROR_MSG("fwrite() failed");
            return NULL;
        }

        bytes_written += result;
    }
    
    fflush(trans_file);

    return trans_file;
} // End function FILE *createTransFile()


/*
 * C L O S E  T R A N S  F I L E
 */
int closeTransFile()
{
    if ( trans_file != NULL )
    {   
        if ( fclose(trans_file) < 0 )
        {   
            DEBUG_MSG("fclose() failed\n");
            return FAILURE;
        }
        else
        {   
            return SUCCESS;
        }
    }

    return SUCCESS;
} // End function int closeTransFile()


/*
 * D E S T R O Y  H A N D L E  T R A N S F E R  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int destroyHandleTransferThread()
{
    GENERAL_MSG("Destroying handle transfer channel thread . . . ");
    if ( pthread_join(handle_transfer_thread, NULL) != 0 )
    {
        ERROR_MSG("pthread_join(handle_handle_transfer_thread) failed");
        return FAILURE;
    }

    pthread_mutex_destroy(&handle_transfer_mutex);

    return SUCCESS;
} // End function int destroyHandleTransferThread()


/*
 * C R E A T E  H A N D L E  T R A N S F E R  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int createHandleTransferThread()
{
    pthread_attr_t attr;
 
    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if( pthread_create( &handle_transfer_thread, &attr, handleTransferThreadFunc, NULL) )
    {
        ERROR_MSG("createHandleTransferThread(): pthread_create failed on handleTransferThreadFunc");
        return FAILURE;
    }

    pthread_attr_destroy(&attr);

    return SUCCESS;
} // End function createHandleTransferThread()


/*
 * C R E A T E  T R A N S  C H A N N E L
 *
 * Returns (int)
 *      Success: a socket file descriptor
 *      Failure: -1
 */
int createTransChannel()
{
   int trans_sockfd;
   struct sockaddr_in addr;
   addr.sin_family      = PF_INET;
   addr.sin_port        = htons(TRANSFER_PORT);
   addr.sin_addr.s_addr = htonl(INADDR_ANY);

   if ( (trans_sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
   {
       ERROR_MSG("socket() failed");
       return FAILURE;
   }

   int on = 1;
   if ( setsockopt(trans_sockfd, SOL_SOCKET, SO_REUSEADDR, &on,
sizeof(int)) < 0 )
   {
       ERROR_MSG("setsockopt(SO_REUSEADDR) failed");
       return FAILURE;
   }

   if ( bind(trans_sockfd, (struct sockaddr *)&addr, sizeof(struct
sockaddr_in)) < 0 )
   {
       ERROR_MSG("bind() failed");
       return FAILURE;
   }

   if ( listen(trans_sockfd, 1000) < 0 )
   {
       ERROR_MSG("listen() failed");
       return FAILURE;
   }

   return trans_sockfd;
} // End function int createTransChannel()


/*
 * H A N D L E  T R A N S F E R  T H R E A D  F U N C  
 *
 * Returns (void)
 *
 */
void *handleTransferThreadFunc(void *arg)
{
    int trans_sockfd, transfer_fd; 
    fd_set trans_set;
    struct sockaddr_in *from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    unsigned int from_len = sizeof(struct sockaddr_in);

    // The amount of time select should wait for packets
    // before timing out
    //struct timeval timeout;
    struct timespec timeout;

    // The main thread should catch these signals.
    sigset_t new;
    sigemptyset(&new);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &new, NULL);

    // Set up the transfer channel socket
    if ( (trans_sockfd = createTransChannel()) < 0 )
    {
        DEBUG_MSG("createTransChannel() failed");
        pthread_exit(NULL);
    }

    while( ! getQuitFlag() ) 
    {
        FD_ZERO(&trans_set);
        FD_SET(trans_sockfd, &trans_set);

        timeout.tv_sec = 1;
        //timeout.tv_usec = 0;
        timeout.tv_nsec = 0;

        //printf("Waiting on select . . .\n");
        sigset_t orig_set;
        sigemptyset(&orig_set);
        int rtn = pselect(trans_sockfd+1, &trans_set, NULL, NULL, &timeout, &orig_set);
        //printf("Select returned %d.\n", rtn);
        
        // Make sure select didn't fail
        if ( rtn <= 0 && errno == EINTR )
        {
            DEBUG_MSG("select() failed");
            continue;
        }


        if ( getQuitFlag() )
        {
            close(trans_sockfd);
            pthread_exit(NULL);
        }

        // Handle packets coming in on the transfer channel (from wigateways)
        if ( FD_ISSET(trans_sockfd, &trans_set) )
        {  
            if ( (transfer_fd = accept(trans_sockfd, (struct sockaddr *)from, &from_len)) < 0 )
            {
                ERROR_MSG("accept() failed");
            }
            else
            {
                //printf("Accepted connection\n");
                char ip_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from->sin_addr.s_addr, ip_buf, sizeof(ip_buf));

                if ( recvFile(transfer_fd) < 0 )
                {
                    DEBUG_MSG("recvFile() failed");
                }
                
                #ifdef CONTROLLER
                if ( sendFile(transfer_fd) < 0 )
                {
                    DEBUG_MSG("sendFile() failed");
                }
                #endif
            }
        }
        FD_CLR(trans_sockfd, &trans_set);
    } // End while( 1 ) 

    return NULL;
} // End function void *handleTransferThreadFuncNew()


/*
 * R E C V  F I L E
 *
 * Returns (int)
 *      Success: the downlink bw
 *      Failure: -1
 */
float recvFile(int trans_sockfd)
{
    char buf[MTU];
    int num_bytes_recvd = -1;
    int bytes_recvd = 0;

    // Connection has been closed on other end
    // Other end send a packet of data size 0
    struct timeval start, end, result;

    gettimeofday(&start, NULL);
    while ( num_bytes_recvd != 0 )
    {
        num_bytes_recvd = recv(trans_sockfd, buf, sizeof(buf), 0);
        if ( num_bytes_recvd < 0 )
        {
            return FAILURE;
        }

        bytes_recvd += num_bytes_recvd;
    }

    //printf("Received %d bytes\n", bytes_recvd);

    // Important: will send a packet of length 0 to tell socket
    // on other end that connection is no longer sending data
    shutdown(trans_sockfd, SHUT_RD);
    gettimeofday(&end, NULL);
    timersub(&end, &start, &result);

    float usecs = ((float)result.tv_usec / (float)1000000);
    float time  = (float)result.tv_sec + usecs;
    float bw    = calculateBandwidth(bytes_recvd, time); // Returned in mbps

    return bw;
} // End function float recvFile()


/*
 * S E N D  F I L E
 *
 * Returns (int)
 *      Success: the size of the file sent
 *      Failure: -1
 */
float sendFile(int trans_sockfd)
{
    int bytes_sent = 0;
    trans_file = createTransFile();

    struct timeval start, end, result;

    gettimeofday(&start, NULL);
    while ( bytes_sent < TRANS_FILE_SIZE ) 
    {
        if ( ( bytes_sent += send(trans_sockfd, trans_file, TRANS_FILE_SIZE - bytes_sent, 0) ) < 0 )
        {   
            ERROR_MSG("send() failed");
            close(trans_sockfd);
            return FAILURE;
        }
    }

    // Important: will send a packet of length 0 to tell socket
    // on other end that connection is no longer sending data
    shutdown(trans_sockfd, SHUT_WR);
    //printf("Sent %d bytes\n", bytes_sent);

    gettimeofday(&end, NULL);
    timersub(&end, &start, &result);

    float usecs = ((float)result.tv_usec / (float)1000000);
    float time  = (float)result.tv_sec + usecs;
    float bw    = calculateBandwidth(bytes_sent, time); // Returned in mbps

    closeTransFile();

    return bw;
} // End function float sendFile()
