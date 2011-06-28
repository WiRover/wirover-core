#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <gps.h>

#include "debug.h"
#include "gps_handler.h"
#include "ping.h"

#if (GPSD_API_MAJOR_VERSION < 4 || GPSD_API_MAJOR_VERSION > 5)
    #error "GPSD version not recognized"
#endif

#define RECONNECT_DELAY 10
#define SECS_TO_USECS   1000000

static int connect_to_gpsd();
static void *gps_thread_func(void *arg);
static void disconnect_from_gpsd();

static pthread_mutex_t gps_data_lock = PTHREAD_MUTEX_INITIALIZER;
static struct gps_fix_t latest_fix;
static struct gps_data_t session;
static int connected = 0;
static pthread_t gps_thread;
static time_t last_update_time = 0;

int init_gps_handler()
{
    if(connected)
        return 0;

    latest_fix.mode = MODE_NOT_SEEN;

    if(pthread_create(&gps_thread, 0, gps_thread_func, 0) != 0)
        return -1;

    return 0;
}

/*
 * Copy the latest GPS fix into a payload structure suitable for sending to the
 * controller.  If GPS data is unavailable, the status field will be set to
 * MODE_NOT_SEEN or MODE_NO_FIX.
 *
 * Returns 0 if the payload contains valid GPS data or -1 otherwise.
 */
int fill_gps_payload(struct gps_payload *dest)
{
    assert(dest);

    if((time(0) - last_update_time) > GPS_DATA_TIMEOUT) {
        dest->status = MODE_NOT_SEEN;
        return -1;
    }

    if(pthread_mutex_lock(&gps_data_lock)) {
        DEBUG_MSG("pthread_mutex_lock failed");
        dest->status = MODE_NOT_SEEN;
        return -1;
    }

    memset(dest, 0, sizeof(*dest));
    dest->status = latest_fix.mode;

    if(latest_fix.mode > 0) {
        dest->latitude = latest_fix.latitude;
        dest->longitude = latest_fix.longitude;
        dest->altitude = latest_fix.altitude;
        dest->track = latest_fix.track;
        dest->speed = latest_fix.speed;
        dest->climb = latest_fix.climb;
    }
    
    pthread_mutex_unlock(&gps_data_lock);

    switch(latest_fix.mode) {
        case MODE_2D:
        case MODE_3D:
            return 0;
        default:
            return -1;
    }
}

/*
 * Attempt to connect to gpsd.  Returns 0 on success, -1 on failure.
 */
static int connect_to_gpsd()
{
    int res;

    if(connected)
        return 0;

#if (GPSD_API_MAJOR_VERSION == 4)
    res = gps_open_r(0, 0, &session);
#elif (GPSD_API_MAJOR_VERSION == 5)
    res = gps_open(0, 0, &session);
#endif
    if(res < 0) {
        DEBUG_MSG("gps_open: %s", gps_errstr(res));
        return -1;
    }

    res = gps_stream(&session, WATCH_ENABLE, 0);
    if(res < 0) {
        DEBUG_MSG("gps_stream: %s", gps_errstr(res));
        gps_close(&session);
        return -1;
    }

    connected = 1;
    return 0;
}

static void disconnect_from_gpsd()
{
    gps_close(&session);
    connected = 0;
}

void *gps_thread_func(void *arg)
{
    connect_to_gpsd();

    while (1) {
        int res;

        // Gracefully handle disconnections
        while(!connected) {
            // A delay of at least 5 seconds is important for two reasons.  1.
            // We don't want to cause a busy loop.  2. If we attempt to
            // reconnect immediately after being disconnected, gps_open will
            // appear to succeed, but gps_poll may block forever.
            sleep(RECONNECT_DELAY);
            connect_to_gpsd();
        }

#if (GPSD_API_MAJOR_VERSION == 4)
        res = gps_waiting(&session);
        if(res < 0) {
            DEBUG_MSG("gps_waiting: %s", gps_errstr(res));
            disconnect_from_gpsd();
            continue;
        } else if(res == 0) {
            usleep(GPS_POLL_INTERVAL);
            continue;
        }

        res = gps_poll(&session);
        if(res < 0) {
            DEBUG_MSG("gps_poll: %s", gps_errstr(res));
            disconnect_from_gpsd();
            continue;
        }
#elif (GPSD_API_MAJOR_VERSION == 5)
        res = gps_waiting(&session, GPS_DATA_TIMEOUT);
        if(res < 0) {
            DEBUG_MSG("gps_waiting: %s", gps_errstr(res));
            disconnect_from_gpsd();
            continue;
        }

        res = gps_read(&session);
        if(res < 0) {
            DEBUG_MSG("gps_read: %s", gps_errstr(res));
            disconnect_from_gpsd();
            continue;
        }
#endif

        if(session.set & LATLON_SET) {
            if(pthread_mutex_lock(&gps_data_lock)) {
                DEBUG_MSG("pthread_mutex_lock failed");
                continue;
            }

            memcpy(&latest_fix, &session.fix, sizeof(struct gps_fix_t));
            last_update_time = time(0);

            // Reset this so that we can catch the next time latitude/longitude is updated.
            session.set = 0;

            pthread_mutex_unlock(&gps_data_lock);
                
            const struct gps_fix_t* fix = &session.fix;
            if(fix->mode > 1) {
                DEBUG_MSG("GPS %f, %f", fix->latitude, fix->longitude);
            }
        }
    }

    return 0;
}

