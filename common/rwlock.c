#include <assert.h>
#include <pthread.h>

#include "rwlock.h"

void obtain_read_lock(struct rwlock* lock)
{
    assert(lock);
    pthread_mutex_lock(&lock->access_lock);

    while(lock->waiting_writers > 0) {
        pthread_cond_wait(&lock->read_cond, &lock->access_lock);
    }
    lock->active_readers++;

    pthread_mutex_unlock(&lock->access_lock);
}

void obtain_write_lock(struct rwlock* lock)
{
    assert(lock);
    pthread_mutex_lock(&lock->access_lock);

    while(lock->active_readers > 0 || lock->active_writers > 0) {
        lock->waiting_writers++;
        pthread_cond_wait(&lock->write_cond, &lock->access_lock);
        lock->waiting_writers--;
    }
    lock->active_writers++;

    pthread_mutex_unlock(&lock->access_lock);
}

void release_read_lock(struct rwlock* lock)
{
    assert(lock);
    pthread_mutex_lock(&lock->access_lock);

    lock->active_readers--;
    if(lock->waiting_writers > 0 && lock->active_readers == 0) {
        pthread_cond_signal(&lock->write_cond);
    }

    pthread_mutex_unlock(&lock->access_lock);
}

void release_write_lock(struct rwlock* lock)
{
    assert(lock);
    pthread_mutex_lock(&lock->access_lock);

    lock->active_writers--;
    if(lock->waiting_writers > 0 && lock->active_writers == 0) {
        pthread_cond_signal(&lock->write_cond);
    } else {
        pthread_cond_broadcast(&lock->read_cond);
    }

    pthread_mutex_unlock(&lock->access_lock);
}

