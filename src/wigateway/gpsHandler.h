/*
 * G P S   H A N D L E R . H
 */

#ifndef GPS_HANDLER_H
#define GPS_HANDLER_H

// Invalidate GPS data after 5 seconds
#define GPS_DATA_TIMEOUT    5

/* Forward declarations */
struct gps_fix_t;
struct gps_data_t;
struct gps_payload;

int initGpsHandler();
void closeGpsHandler();

/* Copies the latest GPS fix to the destination structure. */
void getLatestGpsFix(struct gps_fix_t* dest);
void fillGpsPayload(struct gps_payload* dest);

#endif //GPS_HANDLER_H

