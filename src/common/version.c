#include <arpa/inet.h>

#include "config.h"
#include "version.h"

/*
 * Fill in wirover_version structure with data in network byte order.
 */
struct wirover_version get_wirover_version()
{
    struct wirover_version output;
    output.major = WIROVER_VERSION_MAJOR;
    output.minor = WIROVER_VERSION_MINOR;
    output.revision = WIROVER_VERSION_REVISION;
    return output;
}

int compare_wirover_version(struct wirover_version comp) {
    struct wirover_version version = get_wirover_version();
    if(comp.major > version.major) { return 1; }
    if(comp.major < version.major) { return -1; }
    if(comp.minor > version.minor) { return 1; }
    if(comp.minor < version.minor) { return -1; }
    if(comp.revision > version.revision) { return 1; }
    if(comp.revision < version.revision) { return -1; }
    return 0;
}