#ifndef _STATE_H_
#define _STATE_H_

enum {
    GATEWAY_START = 1 << 0,
    GATEWAY_LEASE_OBTAINED = 1 << 1,
    GATEWAY_CONTROLLER_AVAILABLE = 1 << 2
};

int state;

#endif //_STATE_H_