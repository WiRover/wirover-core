#ifndef _CONFIGURATION_H_
#define _CONFIGURATION_H_

#include <libconfig.h>

#define MAX_CONFIG_PATH_LEN 256
#define DEFAULT_INTERFACE_PRIORITY 0

#if defined(CONTROLLER)
#define CONFIG_FILENAME "wicontroller.conf"
#elif defined(GATEWAY)
#define CONFIG_FILENAME "wigateway.conf"
#elif defined(ROOT)
#define CONFIG_FILENAME "wiroot.conf"
#endif

/* Configuration file keys */
#define CONFIG_WIROOT_ADDRESS       "wiroot-address"
#define CONFIG_WIROOT_PORT          "wiroot-port"
#define CONFIG_DATA_PORT            "data-port"
#define CONFIG_CONTROL_PORT         "control-port"
#define CONFIG_PING_PORT            "ping-port"

/* Default values for missing entries */
#define DEFAULT_WIROOT_ADDRESS      NULL
#define DEFAULT_WIROOT_PORT         8088
#define DEFAULT_DATA_PORT           8080
#define DEFAULT_CONTROL_PORT        8081
#define DEFAULT_PING_PORT           8080

#define DEFAULT_REGISTER_ADDRESS    ""

const config_t*     get_config();
void                close_config();

const char*     get_wiroot_address();
unsigned short  get_wiroot_port();
unsigned short  get_data_port();
unsigned short  get_control_port();
unsigned int    get_ping_interval();
const char*     get_internal_interface();
int             get_interface_priority(const char *ifname);

const char      *get_register_address();

#endif //_CONFIGURATION_H_

