#include <assert.h>
#include <pthread.h>

#include "debug.h"
#include "netlink.h"
#include "rwlock.h"
#include <execinfo.h>

void obtain_read_lock(struct rwlock* lock)
{
    pthread_mutex_lock(&lock->lock);
}

void obtain_write_lock(struct rwlock* lock)
{
    pthread_mutex_lock(&lock->lock);
}

void release_read_lock(struct rwlock* lock)
{
    pthread_mutex_unlock(&lock->lock);
}

void release_write_lock(struct rwlock* lock)
{
    pthread_mutex_unlock(&lock->lock);
}

