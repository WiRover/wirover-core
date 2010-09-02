#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if.h>

#include "debug.h"
#include "netlink.h"
#include "utlist.h"

static void add_interface(struct interface* ife);
static const char* read_dev_name(const char* __restrict__ buffer, char* __restrict__ dest, int destlen);

static struct interface* head_interface = 0;

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


