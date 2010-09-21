#ifndef _CONFIGURATION_H_
#define _CONFIGURATION_H_

#include <libconfig.h>

#define MAX_CONFIG_PATH_LEN 256

#if defined(CONTROLLER)
#define CONFIG_FILENAME "wicontroller.conf"
#elif defined(GATEWAY)
#define CONFIG_FILENAME "wigateway.conf"
#elif defined(ROOT)
#define CONFIG_FILENAME "wiroot.conf"
#endif

const config_t*     get_config();
void                close_config();

const char*     get_wiroot_ip();
unsigned short  get_wiroot_port();
unsigned short  get_base_port();
unsigned int    get_ping_interval();
const char*     get_internal_interface();

#endif //_CONFIGURATION_H_

