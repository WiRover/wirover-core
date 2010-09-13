#ifndef _CONTROLLERS_H_
#define _CONTROLLERS_H_

#include "uthash.h"

struct controller {
    uint32_t        priv_ip;
    uint32_t        pub_ip;
    uint16_t        base_port;

    double          latitude;
    double          longitude;

    UT_hash_handle  hh_ip;
};

void add_controller(uint32_t priv_ip, uint32_t pub_ip, uint16_t base_port,
                    double latitude, double longitude);
int assign_controllers(struct controller** node_list, int list_size,
                       double latitude, double longitude);

#endif //_CONTROLLERS_H_

