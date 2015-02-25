/*
* policyFunctions.h
*/

#ifndef POLICY_FUNCTIONS_H
#define POLICY_FUNCTIONS_H

#include <stdint.h>
#include "flow_table.h"
#include "debug.h"

#define POLICY_PATH "/var/lib/wirover/policy_tbl"

#define DIR_INGRESS   0x1
#define DIR_EGRESS    0x2
#define DIR_BOTH      (DIR_INGRESS | DIR_EGRESS)

#define MAX_POLICY_ENTRY_LENGTH 150

// actions
#define POLICY_ACT_PASS    0x1
#define POLICY_ACT_NAT     0x2
#define POLICY_ACT_ENCAP   0x3
#define POLICY_ACT_DROP    0x5
#define POLICY_ACT_LISP    0x6

// link select options
#define POLICY_LS_WEIGHTED      0x1
#define POLICY_LS_MULTIPATH     0x2
#define POLICY_LS_DUPLICATE     0x3
#define POLICY_LS_FORCED        0x4



enum policy_type {
    POLICY_TYPE_FLOW,
    POLICY_TYPE_DEV
};

typedef struct{
    uint8_t action;
    uint8_t link_select;
    char preferred_link[IFNAMSIZ];
    double rate_limit;

    // flow policy
    uint8_t direction;
    struct flow_tuple ft;
    uint32_t local_netmask;
    uint32_t remote_netmask;

}policy_entry;

int init_policy_table();

int get_policy_by_tuple(struct flow_tuple* ft,  policy_entry *policy, int dir);

//---------DEBUG METHODS------------//

void print_policy_entry(policy_entry * pe);
void print_policies();





#endif //POLICY_FUNCTIONS_H
