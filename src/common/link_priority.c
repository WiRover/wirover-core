#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "debug.h"
#include "link.h"
#include "link_priority.h"
#include "parameters.h"
#include "utils.h"

static struct LinkPriority *linkPriorities = 0;
static int systemPriorityLevel = DEFAULT_PRIORITY;

/*
 * The priority definition in the config file is expected to look like:
 * PRIORITY:{an integer}{whitespace}{comma-separated list of interface names}
 */
int readLinkPriorities(FILE *config)
{
    assert(config);

    char line[CONFIG_FILE_MAX_LINE];

    rewind(config);
    while(!feof(config)) {
        if(fgets(line, CONFIG_FILE_MAX_LINE, config)) {
            const int paramLen = strlen(CONFIG_FILE_PARAM_PRIORITY);
            if(strncmp(line, CONFIG_FILE_PARAM_PRIORITY, paramLen) == 0) {
                char *s = line + paramLen + 1;

                int priority = atoi(s);

                // Skip to the first alphabetic character
                while(*s && !isalpha(*s)) {
                    s++;
                }

                if(isalpha(*s)) {
                    char *saveptr;
                    char *name = strtok_r(s, ", \t", &saveptr);
                    while(name) {
                        chomp(name);

                        struct LinkPriority *lp;
                        HASH_FIND_STR(linkPriorities, name, lp);
                        if(lp) {
                            DEBUG_MSG("Warning: priority for link %s"
                                      " defined multiple times", name);
                            lp->priority = priority;
                        } else {
                            lp = (struct LinkPriority *)malloc(sizeof(*lp));

                            strncpy(lp->name, name, sizeof(lp->name));
                            lp->priority = priority;
                            HASH_ADD_STR(linkPriorities, name, lp);
                        }

                        name = strtok_r(0, ", \t", &saveptr);
                    }
                }
            }
        }
    }

    return SUCCESS;
}

int getLinkPriority(const char *name)
{
    struct LinkPriority *p;
    HASH_FIND_STR(linkPriorities, name, p);
    return p ? p->priority : DEFAULT_PRIORITY;
}

#ifdef GATEWAY

/*
 * Only links with a priority equal to the system priority level can be ACTIVE.
 */
int getSystemPriorityLevel()
{
    return systemPriorityLevel;
}

/*
 * Set the current system priority level and adjust link states accordingly.
 * Links with a lower priority will be marked STANDBY, and links at or
 * above the priority level will be marked ACTIVE.
 */
void setSystemPriorityLevel(int priority)
{
    ASSERT_OR_ELSE(priority >= 0) {
        // A negative priority level is not allowed, as links with negative
        // priorities are never to be used.
        DEBUG_MSG("Warning: attempting to set system priority level to negative value");
        return;
    }

    DEBUG_MSG("changing system priority level from %d to %d", 
            systemPriorityLevel, priority);
    systemPriorityLevel = priority;

    struct link *link = head_link__;
    while(link) {
        if(link->state == ACTIVE && 
                link->priority < systemPriorityLevel) {
            DEBUG_MSG("setting link (%s) state to STANDBY", link->ifname);
            link->state = STANDBY;
        } else if(link->state == STANDBY && 
                link->priority >= systemPriorityLevel) {
            link->state = ACTIVE;
            DEBUG_MSG("setting link (%s) state to ACTIVE", link->ifname);
        }

        assert(link != link->next);
        link = link->next;
    }
}

/*
 * Find the maximum priority level with an available link and set the system
 * priority level to that.
 */
void updateSystemPriorityLevel()
{
    int maxPriority = 0;

    struct link *link = head_link__;
    while(link) {
        if(link->state == ACTIVE || link->state == STANDBY) {
            if(link->priority > maxPriority) {
                maxPriority = link->priority;
            }
        }

        assert(link != link->next);
        link = link->next;
    }

    if(maxPriority != systemPriorityLevel) {
        setSystemPriorityLevel(maxPriority);
    }
}

#endif //GATEWAY

