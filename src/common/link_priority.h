#ifndef _LINK_PRIORITY_H_
#define _LINK_PRIORITY_H_

#include "uthash.h"

#define DEFAULT_PRIORITY    0

struct LinkPriority {
    char    name[IFNAMSIZ];
    int     priority;

    UT_hash_handle  hh;
};

int readLinkPriorities(FILE *config);
int getLinkPriority(const char *name);

#ifdef GATEWAY
int getSystemPriorityLevel();
void setSystemPriorityLevel(int priority);
void updateSystemPriorityLevel();
#endif

#endif //_LINK_PRIORITY_H_

