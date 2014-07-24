#include <libconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fnmatch.h>

#include "config.h"
#include "configuration.h"
#include "debug.h"

static int      is_open = 0;
static config_t config;

static int find_config_file(const char* __restrict__ filename, char* __restrict__ dest, int length);

/*
 * GET CONFIG
 *
 * Opens the config file if it is not already open and returns a config_t
 * pointer, which can be used to read values from it.
 */
const config_t* get_config()
{
#ifdef CONFIG_FILENAME
    if(!is_open) {
        char filename[MAX_CONFIG_PATH_LEN];
        if(find_config_file(CONFIG_FILENAME, filename, sizeof(filename)) == 0) {
            DEBUG_MSG("Failed to find config file %s", CONFIG_FILENAME);
            return 0;
        }

        if(config_read_file(&config, filename) == CONFIG_FALSE) {
            DEBUG_MSG("Failed to parse config file %s", filename);
            DEBUG_MSG("  Error: %s", config_error_text(&config));
            DEBUG_MSG("  Line: %s", config_error_line(&config));
            return 0;
        }

        is_open = 1;
    }

    return &config;
#else
    return 0;
#endif
}       

/*
 * CLOSE CONFIG
 */
void close_config()
{
    if(is_open) {
        config_destroy(&config);
        is_open = 0;
    }
}

/*
 * This function is a wrapper around libconfig's config_lookup_int, which
 * unfortunately changed the parameter type from (long *) to (int *) in a
 * recent version.  Use this wrapper to maintain compatibility across versions
 * of libconfig and on 32-bit and 64-bit architectures.
 */
int config_lookup_int_compat(const config_t *config, const char *path, int *value)
{
    // I think LIBCONFIG_VER_MAJOR is undefined in the older versions which
    // also used (long *) instead of (int *).
#ifndef LIBCONFIG_VER_MAJOR
    long tmp;
    int result = config_lookup_int(config, path, &tmp);
    if(result == CONFIG_TRUE)
        *value = (int)tmp;
    return result;
#else
    return config_lookup_int(config, path, value);
#endif
}

/*
 * This is a wrapper function for config_setting_lookup_int.  See the comment
 * for config_lookup_int_compat for why this is necessary.
 */
int config_setting_lookup_int_compat(const config_setting_t *setting, const char *path, int *value)
{
    // I think LIBCONFIG_VER_MAJOR is undefined in the older versions which
    // also used (long *) instead of (int *).
#ifndef LIBCONFIG_VER_MAJOR
    long tmp;
    int result = config_setting_lookup_int(setting, path, &tmp);
    if(result == CONFIG_TRUE)
        *value = (int)tmp;
    return result;
#else
    return config_setting_lookup_int(setting, path, value);
#endif
}

const char* get_wiroot_address()
{
    const config_t* config = get_config();

    const char* address = DEFAULT_WIROOT_ADDRESS;
    if(!config || config_lookup_string(config, CONFIG_WIROOT_ADDRESS, &address) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read wiroot-address from config file");
    }

    return address;
}

static int __get_port(const char *config_name, unsigned short *port)
{
    const config_t* config = get_config();

    int tmp_port;
    if(!config || config_lookup_int_compat(config, config_name, &tmp_port) == CONFIG_FALSE) {
        DEBUG_MSG("Failed to read %s from config file", config_name);
        return -1;
    } else if(tmp_port < 0 || tmp_port > 0x0000FFFF) {
        DEBUG_MSG("%s in config file is out of range", config_name);
        return -1;
    }

    *port = (unsigned short)tmp_port;
    return 0;
}

unsigned short get_wiroot_port()
{
    unsigned short port = DEFAULT_WIROOT_PORT;
    __get_port(CONFIG_WIROOT_PORT, &port);
    return port;
}

unsigned short get_data_port()
{
    unsigned short port = DEFAULT_DATA_PORT;
    __get_port(CONFIG_DATA_PORT, &port);
    return port;
}

unsigned short get_control_port()
{
    unsigned short port = DEFAULT_CONTROL_PORT;
    __get_port(CONFIG_CONTROL_PORT, &port);
    return port;
}

unsigned int get_ping_interval()
{
    const config_t* config = get_config();

    int interval;
    if(!config || config_lookup_int_compat(config, "ping-interval", &interval) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read ping-interval from config file");
        interval = DEFAULT_PING_INTERVAL;
    } else if(interval <= 0) {
        DEBUG_MSG("ping-interval %d is not acceptable", interval);
        interval = DEFAULT_PING_INTERVAL;
    }

    return interval;
}

unsigned int get_max_ping_failures()
{
    const config_t* config = get_config();
    
    int max_ping_failures;
    if(!config || config_lookup_int_compat(config, CONFIG_MAX_PING_FAILURES, &max_ping_failures) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read max-ping-failures from config file");
        max_ping_failures = DEFAULT_MAX_PING_FAILURES;
    } else if(max_ping_failures <= 0) {
        DEBUG_MSG("max-ping-failures %d is not acceptable", max_ping_failures);
        max_ping_failures = DEFAULT_MAX_PING_FAILURES;
    }
    return max_ping_failures;
}

unsigned int get_mtu()
{
    const config_t* config = get_config();

    int mtu;
    if(!config || config_lookup_int_compat(config, "mtu", &mtu) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read mtu from config file");
        mtu = DEFAULT_MTU;
    } else if(mtu <= 0) {
        DEBUG_MSG("mtu %d is invalid", mtu);
        mtu = DEFAULT_MTU;
    }

    return mtu;
}

const char* get_external_interface()
{
    const config_t* config = get_config();

    const char* interface = 0;
    if(!config || config_lookup_string(config, "external-interface", &interface) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read external-interface from config file");
    }

    return interface;
}

/* 
 * Returns the interface priority from the configuration file.  If the priority
 * is outside the range [-128, 127], then it is mapped to the nearest extreme
 * (-128 or 127).  If the interface is not found, then the default priority
 * value is returned.
 */
int get_interface_priority(const char *ifname)
{
    const config_t *config = get_config();
    if(!config)
        goto default_priority;

    config_setting_t *priority_list = config_lookup(config, "priorities");
    if(!priority_list)
        goto default_priority;

    int list_size = config_setting_length(priority_list);

    int i;
    for(i = 0; i < list_size; i++) {
        config_setting_t *curr_item = config_setting_get_elem(priority_list, i);
        if(!curr_item)
            continue;

        const char *curr_ifname;
        if(!config_setting_lookup_string(curr_item, "interface", &curr_ifname))
            continue;

        if(fnmatch(curr_ifname, ifname, 0) == 0) {
            int curr_priority;
            if(config_setting_lookup_int_compat(curr_item, "priority", &curr_priority)) {
                if(curr_priority < MIN_INTERFACE_PRIORITY)
                    curr_priority = MIN_INTERFACE_PRIORITY;
                else if(curr_priority > MAX_INTERFACE_PRIORITY)
                    curr_priority = MAX_INTERFACE_PRIORITY;

                return curr_priority;
            }
        }
    }

default_priority:
    return DEFAULT_INTERFACE_PRIORITY;
}

unsigned int get_bandwidth_test_interval()
{
    const config_t* config = get_config();

    int interval;
    if(!config || config_lookup_int_compat(config, CONFIG_BANDWIDTH_TEST_INTERVAL, 
                &interval) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read %s from config file", CONFIG_BANDWIDTH_TEST_INTERVAL);
        interval = DEFAULT_BANDWIDTH_TEST_INTERVAL;
    } else if(interval <= 0) {
        DEBUG_MSG("%s %d is not valid", CONFIG_BANDWIDTH_TEST_INTERVAL, interval);
        interval = DEFAULT_BANDWIDTH_TEST_INTERVAL;
    }

    return interval;
}

int get_ping_timeout()
{
    const config_t* config = get_config();

    int timeout;
    if(!config || config_lookup_int_compat(config, CONFIG_PING_TIMEOUT, 
                &timeout) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read %s from config file", CONFIG_PING_TIMEOUT);
        timeout = DEFAULT_PING_TIMEOUT;
    } else if(timeout <= 0) {
        DEBUG_MSG("%s %d is not valid", CONFIG_PING_TIMEOUT, timeout);
        timeout = DEFAULT_PING_TIMEOUT;
    }

    return timeout;
}

int get_link_timeout()
{
    const config_t* config = get_config();

    int timeout;
    if(!config || config_lookup_int_compat(config, CONFIG_LINK_TIMEOUT, 
                &timeout) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read %s from config file", CONFIG_LINK_TIMEOUT);
        timeout = DEFAULT_LINK_TIMEOUT;
    } else if(timeout <= 0) {
        DEBUG_MSG("%s %d is not valid", CONFIG_LINK_TIMEOUT, timeout);
        timeout = DEFAULT_LINK_TIMEOUT;
    }

    return timeout;
}

int get_link_stall_retry_interval()
{
    const config_t* config = get_config();

    int interval;
    if(!config || config_lookup_int_compat(config, CONFIG_LINK_STALL_RETRY_INTERVAL, 
                &interval) == CONFIG_FALSE) {
        DEBUG_MSG("failed to read %s from config file", CONFIG_LINK_STALL_RETRY_INTERVAL);
        interval = DEFAULT_LINK_STALL_RETRY_INTERVAL;
    } else if(interval <= 0) {
        DEBUG_MSG("%s %d is not valid", CONFIG_LINK_STALL_RETRY_INTERVAL, interval);
        interval = DEFAULT_LINK_STALL_RETRY_INTERVAL;
    }

    return interval;
}

const char *get_register_address()
{
    const config_t* config = get_config();

    const char* address = 0;
    if(!config || config_lookup_string(config, CONFIG_REGISTER_ADDRESS, 
                &address) == CONFIG_FALSE)
        return DEFAULT_REGISTER_ADDRESS;
    else
        return address;
}

unsigned short get_register_data_port()
{
    unsigned short port = DEFAULT_REGISTER_DATA_PORT;
    __get_port(CONFIG_REGISTER_DATA_PORT, &port);
    return port;
}

unsigned short get_register_control_port()
{
    unsigned short port = DEFAULT_REGISTER_CONTROL_PORT;
    __get_port(CONFIG_REGISTER_CONTROL_PORT, &port);
    return port;
}

unsigned short get_register_bandwidth_port()
{
    unsigned short port = DEFAULT_REGISTER_BANDWIDTH_PORT;
    __get_port(CONFIG_REGISTER_BANDWIDTH_PORT, &port);
    return port;
}

/*
 * FIND CONFIG FILE
 *
 * Checks the current directory and the system /etc directory for
 * the given filename.
 *
 * On success find_config_file() returns 1 and dest is valid.  On
 * failure it returns 0, and dest is not valid.
 */
int find_config_file(const char* __restrict__ filename, char* __restrict__ dest, int length)
{
    int result;

    // First check if the file is in the current directory
    snprintf(dest, length, "%s", filename);
    result = access(dest, R_OK);
    if(result == 0) {
        return 1;
    }

    // Check for a system config file
    snprintf(dest, length, "/etc/%s", filename);
    result = access(dest, R_OK);
    if(result == 0) {
        return 1;
    }

    return 0;
}


