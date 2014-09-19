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

/* Description of configuration parameters:
 *
 * ...
 * ping-timeout: timeout for a single ping response
 * max-ping-failures: number of failures before making interface INACTIVE
 * link-timeout: idle period before marking interface INACTIVE (on controller)
 */

/* Configuration file keys */
#define CONFIG_WIROOT_ADDRESS               "wiroot-address"
#define CONFIG_WIROOT_PORT                  "wiroot-port"
#define CONFIG_DATA_PORT                    "data-port"
#define CONFIG_CONTROL_PORT                 "control-port"
#define CONFIG_PING_PORT                    "ping-port"
#define CONFIG_REGISTER_ADDRESS             "register-address"
#define CONFIG_REGISTER_DATA_PORT           "register-data-port"
#define CONFIG_REGISTER_CONTROL_PORT        "register-control-port"
#define CONFIG_REGISTER_BANDWIDTH_PORT      "register-bandwidth-port"
#define CONFIG_BANDWIDTH_TEST_INTERVAL      "bandwidth-test-interval"
#define CONFIG_PING_TIMEOUT                 "ping-timeout"
#define CONFIG_MAX_PING_FAILURES            "max-ping-failures"
#define CONFIG_LINK_TIMEOUT                 "link-timeout"
#define CONFIG_LINK_STALL_RETRY_INTERVAL    "link-stall-retry-interval"

#define CONFIG_PACKET_LOG_PATH              "packet-log-path"
#define CONFIG_PACKET_LOG_ENABLED           "packet-log-enabled"
#define CONFIG_STATUS_LOG_ENABLED           "status-log-enabled"

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

#define DEFAULT_REGISTER_ADDRESS        ""
#define DEFAULT_REGISTER_DATA_PORT      0
#define DEFAULT_REGISTER_CONTROL_PORT   0
#define DEFAULT_REGISTER_BANDWIDTH_PORT 0

#define DEFAULT_BANDWIDTH_TEST_INTERVAL   60
#define DEFAULT_PING_TIMEOUT              3
#define DEFAULT_MAX_PING_FAILURES         4
#define DEFAULT_LINK_TIMEOUT              15
#define DEFAULT_LINK_STALL_RETRY_INTERVAL 500

#define DEFAULT_PACKET_LOG_PATH          "/var/log/wirover_packets.log"
#define DEFAULT_PACKET_LOG_ENABLED        0
#define DEFAULT_STATUS_LOG_ENABLED        1

#define DEFAULT_MYSQL_HOST          "localhost"
#define DEFAULT_MYSQL_USER          "wirover"
#define DEFAULT_MYSQL_PASSWORD      ""
#define DEFAULT_MYSQL_DATABASE      "gateways"

#define MIN_INTERFACE_PRIORITY   -128
#define MAX_INTERFACE_PRIORITY   127

const config_t*     get_config();
void                close_config();

int config_lookup_int_compat(const config_t *config, const char *path, int *value);
int config_setting_lookup_int_compat(const config_setting_t *setting, const char *path, int *value);

const char*     get_wiroot_address();
unsigned short  get_wiroot_port();
unsigned short  get_data_port();
unsigned short  get_control_port();
unsigned int    get_ping_interval();
unsigned int    get_max_ping_failures();
unsigned int    get_mtu();
const char*     get_external_interface();
int             get_interface_priority(const char *ifname);
unsigned int    get_bandwidth_test_interval();
int             get_ping_timeout();
int             get_link_timeout();
int             get_link_stall_retry_interval();

const char*     get_packet_log_path();
int             get_packet_log_enabled();
int             get_status_log_enabled();

const char      *get_register_address();
unsigned short  get_register_data_port();
unsigned short  get_register_control_port();
unsigned short  get_register_bandwidth_port();

#endif //_CONFIGURATION_H_

