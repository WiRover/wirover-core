#include <arpa/inet.h>

#include "config.h"
#include "version.h"

/*
 * Fill in wirover_version structure with data in network byte order.
 */
void get_wirover_version_net(struct wirover_version *dest)
{
    dest->major = WIROVER_VERSION_MAJOR;
    dest->minor = WIROVER_VERSION_MINOR;
    dest->revision = htons(WIROVER_VERSION_REVISION);
}

