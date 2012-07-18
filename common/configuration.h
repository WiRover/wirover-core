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

#define CONFIG_MYSQL_HOST           "mysql-host"
#define CONFIG_MYSQL_USER           "mysql-user"
#define CONFIG_MYSQL_PASSWORD       "mysql-password"
#define CONFIG_MYSQL_DATABASE       "mysql-database"

/* Default values for missing entries */
#define DEFAULT_WIROOT_ADDRESS      NULL
#define DEFAULT_WIROOT_PORT         8088
#define DEFAULT_DATA_PORT           8080
#define DEFAULT_CONTROL_PORT        8081
#define DEFAULT_PING_PORT           8080

#define DEFAULT_REGISTER_ADDRESS    ""

#define DEFAULT_MYSQL_HOST          "localhost"
#define DEFAULT_MYSQL_USER          "wirover"
#define DEFAULT_MYSQL_PASSWORD      ""
#define DEFAULT_MYSQL_DATABASE      "gateways"

const config_t*     get_config();
void                close_config();

int config_lookup_int_compat(const config_t *config, const char *path, int *value);

const char*     get_wiroot_address();
unsigned short  get_wiroot_port();
unsigned short  get_data_port();
unsigned short  get_control_port();
unsigned int    get_ping_interval();
unsigned int    get_mtu();
const char*     get_internal_interface();
int             get_interface_priority(const char *ifname);

const char      *get_register_address();

#endif //_CONFIGURATION_H_

