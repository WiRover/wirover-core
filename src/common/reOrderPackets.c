/*
 * R E  O R D E R  P A C K E T S . C
 *
 * This file contains the code to do the re-order buffering when packets
 * are entering or leaving our system
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "reOrderPackets.h"
#include "tunnelInterface.h"
#include "parameters.h"
#include "../common/debug.h"
#include "interface.h"
#include "utils.h"

static char local_buf[MAX_LINE];

//struct timezone tz;
static struct timeval tailTime;
//static int sent_marker[ARRAY_SIZE];

// Buffer and buffer managment variables
//static int     bootstrap = 1;
static int     packet_counter = 0;
static int     head = 0, tail = 0;
static int coded_index = -1;
struct array_element {
    char *packet;
    int size;
    int sent_flag;
    uint32_t seqNo;
    uint16_t code_len;
    int sendfd;
    struct timeval time;
};

static struct array_element buffer[ARRAY_SIZE];

//static struct  timeval time_array[ARRAY_SIZE];
//static char    *packet_array[ARRAY_SIZE];
//static int     size_array[ARRAY_SIZE];
//static int     present_array[ARRAY_SIZE];
//static int     seqNo_array[ARRAY_SIZE];

//static struct timeval *enterTime_array[ARRAY_SIZE];

static long long total_bytes_sent = 0;

// Use sendfd_array to determine socket for transmission.
//static int     sendfd_array[ARRAY_SIZE];

// Thread items
static int              threadRunning = 0;
static pthread_t        reOrderThread;
static pthread_mutex_t  thread_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * D U M P  P R E S E N T  A R R A Y
 *
 * Returns (void):
 *
 */
void dumpReOrderBuffer()
{
    // Dump ReOrder Buffer
    int j;
    int packets_found = 0;

    printf("< ");
    sprintf(local_buf, "< ");
    STATS_MSG(local_buf);

    for(j = 0 ; j < ARRAY_SIZE ; j++)
    {
        if ( buffer[j].packet != NULL )
        {
            packets_found = 1;
            printf("|%d %ld.%06ld| ", j, buffer[j].time.tv_sec, buffer[j].time.tv_usec);
            sprintf(local_buf, "|%d %ld.%06ld| ", j, buffer[j].time.tv_sec, buffer[j].time.tv_usec);
            STATS_MSG(local_buf);
        }
    }

    printf(">");
    sprintf(local_buf, ">");
    STATS_MSG(local_buf);

    printf("\n");
    sprintf(local_buf, "\n");
    STATS_MSG(local_buf);
} // End function dumpReOrderBuffer()


/*
 * C R E A T E  R E O R D E R  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int createReOrderThread()
{
    pthread_attr_t attr;

    if(threadRunning) {
        return SUCCESS;
    }

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if( pthread_create( &reOrderThread, &attr, reOrderThreadFunc, NULL) )
    {
        ERROR_MSG("create thread failed");
        return FAILURE;
    }

    threadRunning = 1;

    pthread_attr_destroy(&attr);

    return SUCCESS;
} // End function int createReOrderThread()


/*
 * D E S T R O Y  R E O R D E R  T H R E A D
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int destroyReOrderThread()
{
    if(!threadRunning) {
        return SUCCESS;
    }

    int i = 0; 
    for( ; i < ARRAY_SIZE ; i++ )
    {
        if ( buffer[i].packet != NULL ) 
        {
            free(buffer[i].packet);
        }
    }

    GENERAL_MSG("Destroying reOrderThread . . . ");
    if ( pthread_join(reOrderThread, NULL) != 0 )
    {
        ERROR_MSG("pthread_join(reOrderThread) failed");
        return FAILURE;
    }

    threadRunning = 0;

    pthread_mutex_destroy(&thread_mutex);
    return SUCCESS;
} // End function destroyReOrderThread()


/*
 * R E O R D E R  I N I T
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int reOrderInit()
{
    // Initialize the packet_array to NULL
    int i;
    for(i = 0; i < ARRAY_SIZE; i++){
        buffer[i].packet = NULL;
        buffer[i].sent_flag = 0;
        buffer[i].sendfd = -1;
        buffer[i].size = 0;
        buffer[i].seqNo = 0;
        //buffer[i].time.tv_sec = 0;
        //buffer[i].time.tv_usec = 0;
        gettimeofday(&buffer[i].time, NULL);
    }

    head = 0;
    tail = 0;

    //struct timeval curtime;
    //gettimeofday(&curtime, NULL);
    //memcpy(&time[head], &curtime, sizeof(struct timeval));
    //    sprintf(local_buf, "INIT ARRAYS:  headTime: %d.%04d tailTime: %d.%04d", time_array[head].tv_sec, (time_array[head].tv_usec/1000), time_array[tail].tv_sec, (time_array[tail].tv_usec/1000));
    //    STATS_MSG(local_buf);

    return SUCCESS;
} // End function int reOrderInit()


/*
 * U P D A T E  T A I L
 *
 * Returns (int)
 *      Success: the index of the tail
 *
 */
int updateTail(int curTail)
{
    int my_index = curTail;

    while( buffer[my_index].sent_flag == 1 )
    {
        buffer[my_index].sent_flag = 0;
        my_index++;
        my_index = my_index % ARRAY_SIZE;
    }

    gettimeofday(&tailTime, NULL);

    return my_index;
} // End function int updateTail()


/*
 * S E N D  P A C K E T S
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int sendPackets(int tunfd)
{
    int rtn;
    int index = tail;
    int to_check = packet_counter;
    struct timeval curTime, diffTime, timeout, leave, result;
   
        sprintf(local_buf, "Checking for %d packets tail: %d head %d.", packet_counter, tail, head); 
        DEBUG_MSG(local_buf);

    // catch the tail pointer up if needed
   while( buffer[tail].packet == NULL && ! getQuitFlag() )
    {
        gettimeofday(&curTime, NULL);
        timersub(&curTime, &buffer[tail].time, &timeout);
        if( (timeout.tv_usec > PACKET_TIMEOUT) || (timeout.tv_sec > 1) )
        {
            buffer[tail].sent_flag = 1;
            pthread_mutex_lock(&thread_mutex);
            tail = updateTail(tail);
            pthread_mutex_unlock(&thread_mutex);
        }
        else
        {
            break;
        }
    }
   
   
    // loop through the packets to see if any are ready to send out
    while( (to_check > 0) && ! getQuitFlag() )
    {
        // this slot is currently empty so we can skip it
      /*  if(buffer[index].packet == NULL)
        {
            // Nothing in this slot, move on
            index++;
            index = index % ARRAY_SIZE;
            if(index >= ARRAY_SIZE) 
            {
                DEBUG_MSG("array index out of bounds\n"); 
            }
            continue;
        }*/

        gettimeofday(&curTime, NULL);
        //printf("curTime: %ld.%06ld\n", curTime.tv_sec, curTime.tv_usec);
        //printf("time_array[index]: %ld.%06ld\n", (time_array[index]).tv_sec, (time_array[index]).tv_usec);
        timersub(&curTime, &buffer[index].time, &diffTime);

        //printf("diffTime: %ld.%06ld\n", diffTime.tv_sec, diffTime.tv_usec);
        if(  (buffer[index].sendfd >= 0 ) )
        {
            // Send the packet
            DEBUG_MSG("Sent SeqNo:%d",buffer[index].seqNo);
            if( (rtn = write(buffer[index].sendfd, buffer[index].packet, buffer[index].size)) < 0)
            {
                ERROR_MSG("write to tunnel failed");
            }
            else
            {
                gettimeofday(&leave, NULL); 
                timersub(&leave, &buffer[index].time, &result);


                total_bytes_sent += rtn;
                /*
                sprintf(local_buf, "Total bytes sent out to internet: %ld", total_bytes_sent);
                STATS_MSG(local_buf);
                */
            }

            // Clean up 
            pthread_mutex_lock(&thread_mutex);
            free(buffer[index].packet);
            buffer[index].packet = NULL;
            buffer[index].sendfd = -1;
            buffer[index].size = 0;
            buffer[index].sent_flag = 1;
            packet_counter--;
            // Update tail pointer
            tail = updateTail(tail);
            pthread_mutex_unlock(&thread_mutex);
           to_check--;
        index++;
        index = index % ARRAY_SIZE;

        }
        else if ( (diffTime.tv_usec/1000 < MAX_DELAY) && (buffer[index].code_len <= 0)){
       //Try to recover the packet
        #ifdef NETWORK_CODING
        coded_index =  getCodedPacket(index);


        if (coded_index == FAILURE) break;
        
        int dist = (coded_index - index + ARRAY_SIZE)%ARRAY_SIZE ;
        
        if (recoverPacket(index, coded_index) == SUCCESS){
      DEBUG_MSG("Recovering Pkt:%d",index);
    char *temp_packet = (char *)malloc(MTU);

      unxorPackets(index, coded_index, temp_packet, MTU);
    // Critical updates - need to be in mutex lock
    pthread_mutex_lock(&thread_mutex);
    //gettimeofday(&buffer[index].time, NULL);
    buffer[index].seqNo = buffer[coded_index].seqNo - dist; //ntohl
    buffer[index].packet = temp_packet;
    buffer[index].sendfd = buffer[coded_index].sendfd;
    buffer[index].size = MTU;
    buffer[index].code_len = 0;
    packet_counter++;
    pthread_mutex_unlock(&thread_mutex);
    // END Critical updates - need to be in mutex lock
     to_check++; 


        } 
      else{
       break;
      }
    #else
    break;
    #endif
        
      }
   /*     else if (buffer[index].code_len <= 0){
        index++;
        index = index % ARRAY_SIZE;
       
        pthread_mutex_lock(&thread_mutex);
        packet_counter--;
        pthread_mutex_unlock(&thread_mutex);
      
        }
     */
   else
        {
            // Packet either too late or lost
        index++;
        index = index % ARRAY_SIZE;
        }


        if(index >= ARRAY_SIZE) 
        {
            DEBUG_MSG("Array index out of bounds 2\n");
        }
/*
        else{
      
            pthread_mutex_lock(&thread_mutex);
            tail = update(tail);
            pthread_mutex_unlock(&thread_mutex);
          DEBUG_MSG("Tail is:%d",tail);
        } 
  */
  }
    return SUCCESS;
} // End function int sendPackets()



/*
 * R E O R D E R  T H R E A D  F U N C
 *
 * Returns (void)
 *
 */
void *reOrderThreadFunc(void *arg)
{
    // The main thread should catch these signals
    sigset_t new;
    sigemptyset(&new);
    sigaddset(&new, SIGINT);
    sigaddset(&new, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &new, NULL);

    struct timeval curTime, diffTime, sleepTime;
    int sleep_time = 0;
    // TODO: if packet shows up after it was marked lost isn't being handled
    //int start = 1;

    reOrderInit();

    // A failsafe for the race condition (see below)
    if ( getQuitFlag() )
    {
        pthread_exit(NULL);
    }

    while( ! getQuitFlag() )
    {
        // Do work of checking for packets here
        if( packet_counter > 0 )
        {
            /*if( start )
            {
                // Init the timeout counter
                gettimeofday(&tailTime, NULL);
                start = 0;
            }*/
            DEBUG_MSG("Pkt counter:%d", packet_counter);
            // Call func to check to see if there are some to send
            if ( sendPackets(getTunnelDescriptor()) < 0 )
            {
                DEBUG_MSG("sendPackets failed\n");
            }
        }
       
        //if( packet_counter > 0 )
         if (0) {
            //calculate the proper amount of time to sleep for
            gettimeofday(&curTime, NULL);

            // CRITICAL SECTION
            pthread_mutex_lock(&thread_mutex);
            timersub(&curTime, &buffer[tail].time, &diffTime);
            pthread_mutex_unlock(&thread_mutex);
            // END CRITICAL SECTION
            struct timeval maxDelay;
            maxDelay.tv_usec = MAX_DELAY * 1000;
            timersub(&maxDelay, &diffTime, &sleepTime);
            sleep_time = (int)sleepTime.tv_usec;
            DEBUG_MSG("Sleeping for %d us",sleep_time);
            if( !( (sleepTime.tv_sec < 0) || (sleepTime.tv_usec < 0) ) )
            {   
                usleep(sleep_time + 1000);

                //sprintf(local_buf, "TAIL INDEX: %d SLEEP_TIME: %d diffTime: %ld.%ld packets: %d", tail, (sleep_time/1000), diffTime.tv_sec, (diffTime.tv_usec/1000) ,packet_counter);
                //STATS_MSG(local_buf);
                //sprintf(local_buf, "\tCurrent time: %ld.%ld.", curTime.tv_sec, curTime.tv_usec);
                //STATS_MSG(local_buf);
                //sprintf(local_buf, "\tTail time   : %ld.%ld.\n", buffer[tail].time.tv_sec, buffer[tail].time.tv_usec);
                //STATS_MSG(local_buf);
            }
        }
        else
        {
            usleep(SLEEP_TIME*1000);
        }
    }

	pthread_exit(NULL);
} // End function void *reOrderThreadFunc()


/*
 * R E O R D E R  P A C K E T
 *
 * Returns (int):
 *      Success: 0
 *      Failure: -1
 *
 */
int reOrderPacket(char *data, int dataLen, int rawsock, uint32_t SeqNo, uint16_t codeLen)
{
    struct timeval curr_time, ref_time, diff_time;
    int order_index, temp_index;
    
	// No... just do this instead.
    order_index = SeqNo % ARRAY_SIZE;  // ntohl(SeqNo)
        // DEBUG_MSG("SeqNo:%d",SeqNo);
    
    if (codeLen > 0) {
       int next_coded_pkt=0;
       next_coded_pkt = (SeqNo + codeLen + 1)% ARRAY_SIZE;
       buffer[next_coded_pkt].code_len = codeLen;
      }
    // If packet showed up after it was marked a loss toss it out
    if ( buffer[order_index].packet != NULL )
    {
        // Send the packet
        int rtn;

        if( (rtn = write(buffer[order_index].sendfd, buffer[order_index].packet, buffer[order_index].size)) < 0)
        {
            ERROR_MSG("write to tunnel failed");
        }
        else
        {
            total_bytes_sent += rtn;
        }
      
        //TODO: check the how long packet has been in buffer and if less than delay the buffer is too small

        // Clean up 
        pthread_mutex_lock(&thread_mutex);
        free(buffer[order_index].packet);
        buffer[order_index].packet = NULL;
        buffer[order_index].sendfd = -1;
        buffer[order_index].size = 0;
        buffer[order_index].sent_flag = 1;
        // Update tail pointer
        tail = updateTail(tail);
        packet_counter--;
        pthread_mutex_unlock(&thread_mutex);

        //DEBUG_MSG("Cleaning out a packet that wasn't sent");
        //sprintf(local_buf, "packet pointer %p packet size %d packet fd %d sent flag %d", buffer[order_index].packet, 
        //            buffer[order_index].size, buffer[order_index].sendfd, buffer[order_index].sent_flag);
        //DEBUG_MSG(local_buf);
        //sprintf(local_buf, "Stored time: %ld:%ld\n", buffer[order_index].time.tv_sec, buffer[order_index].time.tv_usec);
        //DEBUG_MSG(local_buf);
        free(buffer[order_index].packet);
        buffer[order_index].packet = NULL;
    }

    char *temp_packet = (char *)malloc(dataLen);
    memcpy(temp_packet, data, (dataLen));

    // Critical updates - need to be in mutex lock
    pthread_mutex_lock(&thread_mutex);
    gettimeofday(&buffer[order_index].time, NULL);
    buffer[order_index].seqNo = SeqNo; //ntohl
    buffer[order_index].packet = temp_packet;
    buffer[order_index].sendfd = rawsock;
    buffer[order_index].size = dataLen;
    buffer[order_index].code_len = codeLen;
    //if (order_index > tail)
     packet_counter++;
    pthread_mutex_unlock(&thread_mutex);
    // END Critical updates - need to be in mutex lock


    // Save off the original time
    ref_time = buffer[head].time;

    int distance;
    if(head < order_index)
    {
        distance = order_index - head;
    }
    else
    {
        distance = (order_index + ARRAY_SIZE) - head;
    }

    // Update head pointer if needed
    temp_index = head;

    if ( (order_index >= head) || ((order_index < head) && (order_index < tail)) )
    {
        head = (order_index++) % ARRAY_SIZE;
    }

    // Incrementally mark each of the next packets with a linear distribution
    gettimeofday(&curr_time, NULL);
    //printf("LI: curr_time: %ld.%06ld\n", curr_time.tv_sec, curr_time.tv_usec);
    //printf("LI: ref_time: %ld.%06ld\n", ref_time.tv_sec, ref_time.tv_usec);
    timersub(&curr_time, &ref_time, &diff_time);
    diff_time.tv_sec  = (diff_time.tv_sec / distance);
    diff_time.tv_usec = (diff_time.tv_usec / distance);
    if ( head != temp_index )
    {
        struct timeval tmp_time;
        memcpy(&tmp_time, &ref_time, sizeof(struct timeval));
        while ( temp_index != head )
        {
            // CRITICAL SECTION
            pthread_mutex_lock(&thread_mutex);

            // Add the linear increase to the initial value
            timeradd(&tmp_time, &diff_time, &tmp_time);
            memcpy(&buffer[temp_index].time, &tmp_time, sizeof(tmp_time));

            pthread_mutex_unlock(&thread_mutex);
            // END CRITICAL SECTION

            //timeradd(&diff_time, &diff_time, &diff_time);
            temp_index++;
            temp_index = temp_index % ARRAY_SIZE;
        }
    }
    else
    {
        memcpy(&buffer[head].time, &curr_time, sizeof(struct timeval));
    }
   DEBUG_MSG("Head is:%d", head);

    return SUCCESS;
} // End function int reOrderPacket()

int getCodedPacket(int index){
  int ori_index=index, i, dist, code_size=0, coded_packet=-1;

  for (i=1; i<20; i++){
  index++;
  index = index%ARRAY_SIZE;
  code_size = buffer[index].code_len;  
     if(code_size > 0){
      coded_packet = index;
      break;
     }
  }
  
  if ( code_size == 0) return FAILURE;

  dist = (coded_packet - ori_index + ARRAY_SIZE)%ARRAY_SIZE ;
  if ( dist > code_size){
    return FAILURE;
  }
  else {
  //Found the corresponding Coded Packet
  return coded_packet;
  }
}

int recoverPacket(int pkt_index, int coded_index){
  int  i, index, start_index, codeLen;
  
  codeLen = buffer[coded_index].code_len;

 
  start_index = (coded_index - codeLen + ARRAY_SIZE ) % ARRAY_SIZE ;
  index = start_index;
  DEBUG_MSG("Start index:%d,Pkt index:%d, coded_index:%d, codeLen:%d", start_index, pkt_index, coded_index, codeLen);

  for (i=0; i<codeLen; i++){
      if ( (buffer[index].sendfd < 0) && (index != pkt_index)) {
          return FAILURE;
      }
  index++;
  index = index%ARRAY_SIZE;
  DEBUG_MSG("Packet:%d exists",index);
  }
  return SUCCESS;
   
}

int unxorPackets(int pkt_index, int coded_index, char *buf, int len){
  int  i, index, start_index, codeLen;
  
  len = MIN(len, MTU);
  codeLen = buffer[coded_index].code_len;
  
  start_index = (coded_index - codeLen + ARRAY_SIZE ) % ARRAY_SIZE ;
  index = start_index;

  while (index <= coded_index){
    if ((buffer[index].sendfd > 0) && (index != pkt_index)) {
      for (i=0; i<len; i++){
          buf[i] = (buf[i])^(buffer[index].packet[i]);
      }
    }
  index++;
  index = index%ARRAY_SIZE;
  }
return SUCCESS;
}




 
