/*
 *  E V D O _ B U F F E R . C
 *
 *  This file provides the ability to buffer packets going out 3G EVDO
 *  interfaces.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include "../wigateway/interface.h"
#include "evdo_buffer.h"
#include "parameters.h"
#include "../common/debug.h"
#include "utils.h"

#define MAX_BUFFER_SIZE 1000

static pthread_t *sender_threads;


int createSenderThread(struct interface *head, int num_ifs)
{
    int i;
    struct interface * ife = head;

    sender_threads = (pthread_t *)malloc(sizeof(pthread_t) * num_ifs);

    for( i = 0 ; i < num_ifs ; i++ )
    {
        while(ife->is_valid != 1)
        {
            ife = ife->next;
        }

        if( pthread_create( &sender_threads[i], NULL, bufferThreadFunc, (void *)ife) )
        {
            ERROR_MSG("pthread_create failed on bufferThreadFunc");
            return FAILURE;
        }
        pthread_mutex_init(&ife->lock_mutex, NULL);
        pthread_mutex_init(&ife->condition_mutex, NULL);
        pthread_cond_init(&ife->condition_cond, NULL);

        ife = ife->next;
    }
    return SUCCESS;
}


int destroySenderThread(struct interface *head, int num_ifs)
{
    int i;
    for( i = 0; i < num_ifs ; i++ )
    {
        if ( pthread_join(sender_threads[i], NULL) != 0 )
        {
            ERROR_MSG("pthread_join(sender_threads) failed");
            return FAILURE;
        }
    }

    //free the sender_threads array
    free(sender_threads);

    struct interface *ife = head;
    while(ife)
    {
        if(ife->is_valid == 1)
        {
            pthread_mutex_destroy(&ife->lock_mutex);
            pthread_mutex_destroy(&ife->condition_mutex);
            pthread_cond_destroy(&ife->condition_cond);
        }
        ife = ife->next;
    }
    return SUCCESS;
}


/*
 *              M Y S E N D T O 
 */
int mySendto(int fd, char *data, int size, int flags, struct sockaddr *addr, int size_addr, struct interface *ife)
{
    ife->buf_temp = (struct buffer_node *)malloc(sizeof(struct buffer_node));
    ife->buf_temp->fd = fd;
    ife->buf_temp->data = (char *)malloc(size);
    memcpy(ife->buf_temp->data, data, size);
    ife->buf_temp->size = size;
    ife->buf_temp->flags = flags;
    ife->buf_temp->addr = (struct sockaddr *)malloc(size_addr);
    memcpy(ife->buf_temp->addr, addr, size_addr);
    ife->buf_temp->size_addr = size_addr;

    pthread_mutex_lock(&ife->lock_mutex);
    if(ife->buffer_size == 0)
    {
        ife->buf_head = ife->buf_temp;
    }

    if(ife->buf_tail != NULL)
    {		
        ife->buf_tail->next = ife->buf_temp;
    }

    ife->buf_tail = ife->buf_temp;
    ife->buffer_size++;

    if(ife->max_buf_size < ife->buffer_size)
    {
        ife->max_buf_size = ife->buffer_size;
    }

    pthread_mutex_unlock(&ife->lock_mutex);

    return SUCCESS;
} // End function int mySendto()


/*
 *              M Y W R I T E
 */
int myWrite(int fd, char *data, int size, struct interface *ife)
{
    ife->buf_temp = (struct buffer_node *)malloc(sizeof(struct buffer_node));
    ife->buf_temp->fd = fd;
    ife->buf_temp->data = (char *)malloc(size);
    memcpy(ife->buf_temp->data, data, size);
    ife->buf_temp->size = size;

    pthread_mutex_lock(&ife->lock_mutex);
    if(ife->buffer_size == 0)
    {
        ife->buf_head = ife->buf_temp;
    }

    if(ife->buf_tail != NULL)
    {		
        ife->buf_tail->next = ife->buf_temp;
    }

    ife->buf_tail = ife->buf_temp;
    ife->buffer_size++;
    pthread_mutex_unlock(&ife->lock_mutex);

    return SUCCESS;
} // End function int myWrite()


/*
 * B U F F E R  T H R E A D  F U N C
 *
 * Returns (void *): NULL
 *
 */
void *bufferThreadFunc(void *arg)
{
    int rtn;
    struct interface *ife = (struct interface *)arg;

    //while( ! getNeedToQuit() )
    while( 1 )
    {
        pthread_mutex_lock(&ife->condition_mutex);
        while( ife->buffer_size < 1 )
        {
            // Wait
            pthread_cond_wait( &ife->condition_cond, &ife->condition_mutex);
        }
        pthread_mutex_unlock(&ife->condition_mutex);

        if( USE_PROXY )
        {
            rtn = sendto(ife->buf_head->fd, ife->buf_head->data, 
                ife->buf_head->size, ife->buf_head->flags, 
                ife->buf_head->addr, ife->buf_head->size_addr);
        }
        else
        {
            rtn = write(ife->buf_head->fd, ife->buf_head->data, ife->buf_head->size);
        }

        if(rtn < 0)
        {
            ERROR_MSG("sendto failed");
            break;
        }
        else
        {
            ife->total_sent++;
            ife->total_bytes += ife->buf_head->size;
            if( (ife->total_sent % 25) == 0 )
            {
            }

            //TODO: should clean up this code in the locks
            pthread_mutex_lock(&ife->lock_mutex);
            if(ife->buf_head == ife->buf_tail)
            {
                ife->buf_tail = NULL;
            }

            ife->buf_temp = ife->buf_head;
            free(ife->buf_head->data);

            if( USE_PROXY )
            {
                free(ife->buf_head->addr);
            }

            ife->buf_head = ife->buf_temp->next;
            free(ife->buf_temp);

            ife->buffer_size--;
            pthread_mutex_unlock(&ife->lock_mutex);
        }
    } // End while ( ! need_to_quit )

    return NULL;
} // End function void *bufferThreadFunc()
