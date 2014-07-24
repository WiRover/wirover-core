#ifndef SELECTINTERFACE_H
#define SELECTINTERFACE_H

#include "flow_table.h"


//These are defined separately by both the controller and gateway
//Their purpose is to choose source and destination interfaces for
//outgoing packets, this includes handling failover etc. when an
//interface is no longer active
struct interface *select_src_interface(struct flow_entry *fe);
struct interface *select_dst_interface(struct flow_entry *fe);

#endif /* SELECTINTERFACE_H */