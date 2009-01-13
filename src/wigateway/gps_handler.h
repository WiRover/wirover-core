#ifndef GPS_HANDLER_H
#define GPS_HANDLER_H


/* Forward declarations */
struct gps_fix_t;
struct gps_data_t;
struct gps_payload;

int init_gps_handler();
int fill_gps_payload(struct gps_payload *dest);

#endif //GPS_HANDLER_H

