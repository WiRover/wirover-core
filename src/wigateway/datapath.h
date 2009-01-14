#ifndef DATAPATH_H
#define DATAPATH_H

#include "tunnelInterface.h"

int handlePackets(struct tunnel *tun);
int start_data_thread();
#endif