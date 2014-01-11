/*
 * T R A N S F E R . H
 */

#ifndef TRANSFER_H 
#define TRANSFER_H

#define BW_PERIOD 5

int measureBandwidth(struct interface *ife);
int createTransferThread();
int destroyTransferThread();

#endif
