/* Required for htobe64 */
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <endian.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>

#include "debug.h"
#include "ping.h"

/*
 * Searches /proc/net/dev for stats for the requested interface.
 *
 * Returns 0 on success and -1 on failure.  If successful, the results are
 * written to dest in network byte order.
 */
int fill_passive_payload(const char *ifname, struct passive_payload *dest)
{
    int retval = -1;

    FILE *file = fopen(PROC_NET_DEV, "r");
    if(!file) {
        ERROR_MSG("Failed to open " PROC_NET_DEV);
        return -1;
    }

    char *buffer = malloc(BUFSIZ);
    if(!buffer) {
        DEBUG_MSG("out of memory");
        return -1;
    }

    // The first two lines are headers
    fgets(buffer, BUFSIZ, file);
    fgets(buffer, BUFSIZ, file);

    char *rx_stats[PROC_NET_DEV_STAT_COLS];
    char *tx_stats[PROC_NET_DEV_STAT_COLS];

    while(!feof(file)) {
        if(!fgets(buffer, BUFSIZ, file))
            break;

        char *saveptr;

        char *dev = strtok_r(buffer, " :", &saveptr);
        if(!dev)
            continue;

        if(strncmp(ifname, dev, IFNAMSIZ) != 0)
            continue;

        int i;
        for(i = 0; i < 8; i++) {
            rx_stats[i] = strtok_r(0, " ", &saveptr);
            if(!rx_stats[i])
                continue;
        }
        for(i = 0; i < 8; i++) {
            tx_stats[i] = strtok_r(0, " ", &saveptr);
            if(!tx_stats[i])
                continue;
        }

        dest->bytes_tx = htobe64(strtoull(tx_stats[0], 0, 10));
        dest->bytes_rx = htobe64(strtoull(rx_stats[0], 0, 10));
        dest->packets_tx = htonl(strtoul(tx_stats[1], 0, 10));
        dest->packets_rx = htonl(strtoul(rx_stats[1], 0, 10));

        retval = 0;
        break;
    }

    free(buffer);
    fclose(file);

    return retval;
}

