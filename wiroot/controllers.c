#include <stdint.h>
#include <stdlib.h>

#include "debug.h"
#include "controllers.h"

static struct controller*    controllers_ip_hash = 0;

/*
 * ADD CONTROLLER
 *
 * Adds a controller to list of available controllers.
 */
void add_controller(const ipaddr_t* priv_ip, const ipaddr_t* pub_ip, 
        uint16_t base_port, double latitude, double longitude)
{
    struct controller* controller;
    int is_new = 0;

    HASH_FIND(hh_ip, controllers_ip_hash, priv_ip, sizeof(*priv_ip), controller);
    if(!controller) {
        controller = (struct controller*)malloc(sizeof(struct controller));
        ASSERT_OR_ELSE(controller) {
            DEBUG_MSG("out of memory");
            return;
        }
        
        is_new = 1;
    }

    copy_ipaddr(priv_ip, &controller->priv_ip);
    copy_ipaddr(pub_ip, &controller->pub_ip);
    controller->base_port = base_port;
    controller->latitude = latitude;
    controller->longitude = longitude;

    if(is_new) {
        HASH_ADD(hh_ip, controllers_ip_hash, priv_ip, sizeof(*priv_ip), controller);
    }
}

/*
 * ASSIGN CONTROLLERS
 *
 * Assigns a gateway to one or more controllers.  controller_list must be a valid
 * array of controller pointers, which will be filled in by this function.
 * assign_controllers() will return the number of controllers written to the
 * array.
 *
 * TODO: more intelligent assignment, currently we just grab the first
 * list_size controllers
 */
int assign_controllers(struct controller** controller_list, int list_size, double latitude, double longitude)
{
    ASSERT_OR_ELSE(controller_list) {
        DEBUG_MSG("null pointer");
        return 0;
    }

    int controllers = 0;

    struct controller* curr_controller = controllers_ip_hash;
    while(curr_controller && controllers < list_size) {
        controller_list[controllers++] = curr_controller;

        curr_controller = curr_controller->hh_ip.next;
    }

    return controllers;
}

