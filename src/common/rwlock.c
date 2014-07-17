#include <assert.h>
#include <pthread.h>

#include "rwlock.h"

void obtain_read_lock(struct rwlock* lock)
{
    pthread_rwlock_rdlock(&lock->lock);
}

void obtain_write_lock(struct rwlock* lock)
{
    pthread_rwlock_wrlock(&lock->lock);
}

void upgrade_read_lock(struct rwlock* lock)
{
    pthread_rwlock_unlock(&lock->lock);
    pthread_rwlock_wrlock(&lock->lock);
}

void downgrade_write_lock(struct rwlock* lock)
{
    pthread_rwlock_unlock(&lock->lock);
    pthread_rwlock_rdlock(&lock->lock);
}

void release_read_lock(struct rwlock* lock)
{
    pthread_rwlock_unlock(&lock->lock);
}

void release_write_lock(struct rwlock* lock)
{
    pthread_rwlock_unlock(&lock->lock);
}

