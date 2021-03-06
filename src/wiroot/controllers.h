#ifndef _CONTROLLERS_H_
#define _CONTROLLERS_H_

#include "ipaddr.h"
#include "uthash.h"

struct controller {
    ipaddr_t        priv_ip;
    ipaddr_t        pub_ip;

    uint16_t        unique_id;
    uint16_t        data_port;
    uint16_t        control_port;

    double          latitude;
    double          longitude;

    UT_hash_handle  hh_ip;
};

void add_controller(uint16_t unique_id, const ipaddr_t* priv_ip, const ipaddr_t* pub_ip, uint16_t data_port,
                    uint16_t control_port, double latitude, double longitude);
struct controller *assign_controller(double latitude, double longitude);

#endif //_CONTROLLERS_H_

