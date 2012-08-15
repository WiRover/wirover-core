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

static const char *PING_ERR_STR[] = {
    "PING_ERR_OK",
    "PING_ERR_TOO_SHORT",
    "PING_ERR_BAD_NODE",
    "PING_ERR_BAD_LINK",
    "PING_ERR_BAD_HASH",
    "PING_ERR_NOT_PING",
    "PING_ERR_BAD_TYPE",
};  

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

/*
 * Copies the private key into the pkt->digest field, computes the SHA hash
 * and fills the pkt->digest field in with the result.
 */
void fill_ping_digest(struct ping_packet *pkt, const char *data, int len, const unsigned char *key)
{
    memcpy(pkt->digest, key, sizeof(pkt->digest));

    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, data, len);
    SHA256_Final(pkt->digest, &sha);
}

/*
 * Verifies sender of ping packet by computing keyed SHA hash.
 *
 * Returns 0 on match.
 */
int verify_ping_sender(struct ping_packet *pkt, const char *data, int len, const unsigned char *key)
{
    unsigned char rcv_digest[SHA256_DIGEST_LENGTH];
    memcpy(rcv_digest, pkt->digest, sizeof(pkt->digest));

    memcpy(pkt->digest, key, SHA256_DIGEST_LENGTH);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, data, len);

    unsigned char cmp_digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(cmp_digest, &sha);

    int result = memcmp(rcv_digest, cmp_digest, SHA256_DIGEST_LENGTH);

    memcpy(pkt->digest, rcv_digest, SHA256_DIGEST_LENGTH);

    return result;
}

int iszero(const unsigned char *buffer, int len)
{
    int i;
    for(i = 0; i < len; i++) {
        if(buffer[i])
            return 0;
    }

    return 1;
}

const char *ping_err_str(int error)
{
    if(error < 0 || error >= MAX_PING_ERR)
        return "INVALID_ERROR_CODE";
    else
        return PING_ERR_STR[error];
}

