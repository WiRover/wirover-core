#include <stddef.h>

#include "../common/debug.h"
#include "packetBuffer.h"
#include "../common/debug.h"


int initPacketBuffer(struct buffer_storage *packet_buffer[]) {
    int i;
    for(i = 0; i < PACKET_BUFFER_SIZE; i++) {
        packet_buffer[i] = NULL;
    }

    return 0;
}

int addSeqNum(struct buffer_storage *packet_buffer[], int num) {
    int index = num % PACKET_BUFFER_SIZE;

    struct buffer_storage *bs;
    if(packet_buffer[index] == NULL) {
        struct buffer_storage *bs = malloc(sizeof(struct buffer_storage));
        bs->seq_no = num;
        packet_buffer[index] = bs;
        return ADDED;
    }


    bs = packet_buffer[index];

    //What if the seq numbers wrap around
    if(num <= bs->seq_no && num > bs->seq_no - WRAP_AROUND_BOUND) {
        return NOT_ADDED;
    }

    bs->seq_no = num;

    return ADDED;
}

