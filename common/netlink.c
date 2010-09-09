#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"
#include "netlink.h"
#include "utlist.h"

static void add_interface(struct interface* ife);
static const char* read_dev_name(const char* __restrict__ buffer, char* __restrict__ dest, int destlen);

static struct interface* head_interface = 0;

static pthread_mutex_t list_access_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int    active_readers = 0;
static unsigned int    active_writers = 0;
static unsigned int    waiting_writers = 0;
static pthread_cond_t  list_read_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  list_write_cond = PTHREAD_COND_INITIALIZER;

/*
 * INIT INTERFACE LIST
 *
 * Creates an initial list of interfaces based on those in /proc/net/dev.
 */
int init_interface_list()
{
    FILE* proc_file;
    char buffer[512];

    proc_file = fopen("/proc/net/dev", "r");
    if(!proc_file) {
        ERROR_MSG("Failed to open /proc/net/dev for reading");
        return -1;
    }

    // Throw away the first two lines
    fgets(buffer, sizeof(buffer), proc_file);
    fgets(buffer, sizeof(buffer), proc_file);

    while(fgets(buffer, sizeof(buffer), proc_file)) {
        char name[IFNAMSIZ];
        read_dev_name(buffer, name, sizeof(name));

        struct interface* ife;
        ife = create_interface(name);
        if(!ife) {
            continue;
        }

        add_interface(ife);
    }

    return 0;
}

/*
 * CREATE INTERFACE
 *
 * Allocates space for an interface structure and fills in the name.  This does
 * not add it to any list.
 */
struct interface* create_interface(const char* name)
{
    struct interface* ife;

    ife = (struct interface*)malloc(sizeof(struct interface));
    ASSERT_OR_ELSE(ife) {
        DEBUG_MSG("out of memory");
        return 0;
    }

    strncpy(ife->name, name, sizeof(ife->name));

    return ife;
}

static void add_interface(struct interface* ife)
{
    DEBUG_MSG("Adding interface %s", ife->name);
    DL_APPEND(head_interface, ife);
}

/*
 * READ DEV NAME
 *
 * Reads the device name from a line from /proc/net/dev.
 *
 * Returns a pointer to the next character after the name.
 */
static const char* read_dev_name(const char* __restrict__ buffer, char* __restrict__ dest, int destlen)
{
    memset(dest, 0, destlen);

    int i = 0;
    while(isspace(buffer[i])) {
        i++;
    }

    // Hit the end of the string -- this would be very unusual.
    if(buffer[i] == 0) {
        return &buffer[i];
    }

    int j = 0;
    while(isalnum(buffer[i]) && j < destlen - 1) {
        dest[j++] = buffer[i++];
    }

    return &buffer[i];
}

struct interface* obtain_read_lock()
{
    pthread_mutex_lock(&list_access_lock);

    while(waiting_writers > 0) {
        pthread_cond_wait(&list_read_cond, &list_access_lock);
    }
    active_readers++;

    pthread_mutex_unlock(&list_access_lock);

    return head_interface;
}

struct interface* obtain_write_lock()
{
    pthread_mutex_lock(&list_access_lock);

    while(active_readers > 0 || active_writers > 0) {
        waiting_writers++;
        pthread_cond_wait(&list_write_cond, &list_access_lock);
        waiting_writers--;
    }
    active_writers++;
    
    pthread_mutex_unlock(&list_access_lock);

    return head_interface;
}

void release_read_lock()
{
    pthread_mutex_lock(&list_access_lock);

    active_readers--;
    if(waiting_writers > 0 && active_readers == 0) {
        pthread_cond_signal(&list_write_cond);
    }

    pthread_mutex_unlock(&list_access_lock);
}

void release_write_lock()
{
    pthread_mutex_lock(&list_access_lock);

    active_writers--;
    if(waiting_writers > 0) {
        pthread_cond_signal(&list_write_cond);
    } else {
        pthread_cond_broadcast(&list_read_cond);
    }

    pthread_mutex_unlock(&list_access_lock);
}


