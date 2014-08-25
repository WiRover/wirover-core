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
void add_controller(uint16_t unique_id, const ipaddr_t* priv_ip, const ipaddr_t* pub_ip, 
        uint16_t data_port, uint16_t control_port, double latitude, double longitude)
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
    controller->data_port = data_port;
    controller->control_port = control_port;
    controller->latitude = latitude;
    controller->longitude = longitude;
    controller->unique_id = unique_id;
    DEBUG_MSG("Adding controller with unique id %d",unique_id);
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
 * controller
 */
struct controller *assign_controller(double latitude, double longitude)
{
    return controllers_ip_hash;
}

