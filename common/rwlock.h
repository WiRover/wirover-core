#ifndef _RWLOCK_H_
#define _RWLOCK_H_

#include <pthread.h>

struct rwlock {
    pthread_mutex_t     access_lock;
    unsigned int        active_readers;
    unsigned int        active_writers;
    unsigned int        waiting_writers;
    pthread_cond_t      read_cond;
    pthread_cond_t      write_cond;
};

#define RWLOCK_INITIALIZER                          \
{                                                   \
    .access_lock = PTHREAD_MUTEX_INITIALIZER,       \
    .active_readers = 0,                            \
    .active_writers = 0,                            \
    .waiting_writers = 0,                           \
    .read_cond = PTHREAD_COND_INITIALIZER,          \
    .write_cond = PTHREAD_COND_INITIALIZER,         \
}

void obtain_read_lock(struct rwlock* lock);
void obtain_write_lock(struct rwlock* lock);
void release_read_lock(struct rwlock* lock);
void release_write_lock(struct rwlock* lock);

#endif //_RWLOCK_H_

