/*  vim: set et ts=4 sw=4:
 *
 * G P S   H A N D L E R . C
 */

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

#include "../common/debug.h"
#include "../common/parameters.h"
#include "../common/udp_ping.h"
#include "../common/utils.h"
#include "gpsHandler.h"

#define RECONNECT_DELAY 10
#define SECS_TO_USECS   1000000

#ifdef CONFIG_USE_GPSD
#include <gps.h>

// Internal functions
int gpsConnect();
void* gpsDataCollector(void* arg);

static pthread_mutex_t gpsDataLock = PTHREAD_MUTEX_INITIALIZER;
static struct gps_fix_t latestFix;
static struct gps_data_t *session = 0;
static pthread_t gpsThread;
static time_t lastValidTime = 0;

/*
 * I N I T   G P S   H A N D L E R
 */
int initGpsHandler()
{
    /* Checks if initGpsHandler has already been called. */
    if(session) {
        return SUCCESS;
    }

    latestFix.mode = MODE_NOT_SEEN; /* indicates that GPS data is invalid */ 

    if (pthread_create(&gpsThread, 0, gpsDataCollector, 0) != 0) {
        return FAILURE;
    }

    return SUCCESS;
} /* end of function initGpsHandler */

/*
 * GPS CONNECT
 *
 * Opens a connection to the GPS server and initiates auto updates.
 * Returns SUCCESS or FAILURE.
 *
 * Does nothing and returns SUCCESS if we are already connected.
 */
int gpsConnect()
{
    if(session) {
        return SUCCESS;
    }

#if (GPSD_API_MAJOR_VERSION >= 4)
    session = malloc(sizeof(*session));
    if(!session)
        return FAILURE;

    if(gps_open(0, 0, session) != 0) {
        free(session);
        session = 0;
        return FAILURE;
    }

    if(gps_stream(session, WATCH_ENABLE, 0) < 0) {
        gps_close(session);
        free(session);
        session = 0;
        return FAILURE;
    }
#else
    session = gps_open(0, 0);
    if(!session)
        return FAILURE;

    if(gps_query(session, "w+x\n") < 0) {
        gps_close(session);
        session = 0;
        return FAILURE;
    }
#endif

    DEBUG_MSG("Connected to gpsd");
    return SUCCESS;
}

/*
 * C L O S E   G P S   H A N D L E R
 */
void closeGpsHandler()
{
    if(session) {
        gps_close(session);
#if (GPSD_API_MAJOR_VERSION >= 4)
        free(session);
#endif
        session = 0;

        pthread_mutex_destroy(&gpsDataLock);
    }
} /* end of function closeGpsHandler */

/*
 * G E T   L A T E S T   G P S   F I X
 */
void getLatestGpsFix(struct gps_fix_t* dest)
{
    ASSERT_OR_ELSE(dest) {
        return;
    }

    if(pthread_mutex_lock(&gpsDataLock)) {
        /* This is not likely to happen. */
        dest->mode = MODE_NOT_SEEN;
        return;
    }

    memcpy(dest, &latestFix, sizeof(*dest));

    // Invalidate the data if it is too old.
    if( (time(0) - lastValidTime) > GPS_DATA_TIMEOUT ) {
        dest->mode = MODE_NOT_SEEN;
    }

    pthread_mutex_unlock(&gpsDataLock);
} /* end of function getLatestGpsFix */

/*
 * F I L L   G P S   D A T A   P A Y L O A D
 */
void fillGpsPayload(struct gps_payload* dest)
{
    ASSERT_OR_ELSE(dest) {
        return;
    }

    if(pthread_mutex_lock(&gpsDataLock)) {
        /* This is not likely to happen. */
        dest->status = MODE_NOT_SEEN;
        return;
    }

    memset(dest, 0, sizeof(struct gps_payload));
    dest->status = latestFix.mode;

    if(latestFix.mode > 0) {
        dest->latitude = latestFix.latitude;
        dest->longitude = latestFix.longitude;
        dest->altitude = latestFix.altitude;
        dest->track = latestFix.track;
        dest->speed = latestFix.speed;
        dest->climb = latestFix.climb;
    }
    
    // Invalidate the data if it is too old.
    if( (time(0) - lastValidTime) > GPS_DATA_TIMEOUT ) {
        dest->status = MODE_NOT_SEEN;
    }

    pthread_mutex_unlock(&gpsDataLock);
} /* end function fillGpsPayload */

/*
 * G P S   D A T A   C O L L E C T O R
 */
void* gpsDataCollector(void* arg)
{
    while (1) {
        // Gracefully handle disconnections
        while(!session) {
            // A delay of at least 5 seconds is important for two reasons.  1.
            // We don't want to cause a busy loop.  2. If we attempt to
            // reconnect immediately after being disconnected, gps_open will
            // appear to succeed, but gps_poll may block forever.
            sleep(RECONNECT_DELAY);
            gpsConnect();
        }

#if (GPSD_API_MAJOR_VERSION >= 4)
        if(!gps_waiting(session, GPS_DATA_TIMEOUT * SECS_TO_USECS) ||
                gps_read(session) <= 0) {
            // We will disconnect and attempt to reconnect on the next loop
            gps_close(session);
            free(session);
            session = 0;
            continue;
        }
#else
        if(gps_poll(session) != 0) {
            // We will disconnect and attempt to reconnect on the next loop
            gps_close(session);
            session = 0;
            continue;
        }
#endif

        if(session->set & LATLON_SET) {
            if(pthread_mutex_lock(&gpsDataLock)) {
                // This is not likely to happen.
                DEBUG_MSG("pthread_mutex_lock failed");
                return 0;
            }
     
            memcpy(&latestFix, &session->fix, sizeof(struct gps_fix_t));
            time(&lastValidTime);

            // Reset this so that we can catch the next time latitude/longitude is updated.
            session->set = 0;
            
            pthread_mutex_unlock(&gpsDataLock);

            struct gps_fix_t* fix = &session->fix;
            if(fix->mode > 1) {
                STATS_MSG("GPS,%lu,%f,%d,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f",
                        time(0),
                        fix->time,
                        fix->mode,
                        fix->ept,
                        fix->latitude,
#if (GPSD_API_MAJOR_VERSION >= 4)
                        fix->epy,
#else
                        0.0,
#endif
                        fix->longitude,
#if (GPSD_API_MAJOR_VERSION >= 4)
                        fix->epx,
#else
                        0.0,
#endif
                        fix->altitude,
                        fix->epv,
                        fix->track,
                        fix->epd,
                        fix->speed,
                        fix->eps,
                        fix->climb,
                        fix->epc);
            }
        }
    }

    return 0;
} /* end of function gpsDataCollector */

#else

int initGpsHandler() {return FAILURE; }
void closeGpsHandler() {};

void getLatestGpsFix(struct gps_fix_t* dest) {};
void fillGpsPayload(struct gps_payload* dest) {};

#endif

