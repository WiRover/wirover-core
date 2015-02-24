#ifndef SELECTINTERFACE_H
#define SELECTINTERFACE_H

#include "flow_table.h"

struct interface *select_mp_interface(struct interface *head);
struct interface *select_weighted_interface(struct interface *head);
int select_all_interfaces(struct interface *head, struct interface ** dst, int size);

//These are defined separately by both the controller and gateway
//Their purpose is to choose source and destination interfaces for
//outgoing packets, this includes handling failover etc. when an
//interface is no longer active. They return the number of interfaces
//copied to dst, up to a maximum of size.
int select_src_interface(struct flow_entry *fe, struct interface ** dst, int size);
int select_dst_interface(struct flow_entry *fe, struct interface ** dst, int size);

#endif /* SELECTINTERFACE_H */
