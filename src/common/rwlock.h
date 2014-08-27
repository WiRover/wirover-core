#ifndef _RWLOCK_H_
#define _RWLOCK_H_

#include <pthread.h>

/* This read-write lock code is just a wrapper around the pthread rwlock
 * functions.  New code should use the pthread functions directly.  What
 * happened was that I implemented read-write locks without realizing that the
 * pthreads library provides an implementation.  After running into multiple
 * bugs with my implementation, I decided just to call the pthreads functions. */

struct rwlock {
    pthread_mutex_t lock;
};

#define RWLOCK_INITIALIZER                          \
{                                                   \
    .lock = PTHREAD_MUTEX_INITIALIZER,             \
}

void obtain_read_lock(struct rwlock* lock);
void obtain_write_lock(struct rwlock* lock);
void release_read_lock(struct rwlock* lock);
void release_write_lock(struct rwlock* lock);

#endif //_RWLOCK_H_

