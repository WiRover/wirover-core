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

#define NO_MATCH -1

#define MAX_ALG_NAME_LEN   16

#define MAX_POLICY_ENTRY_LENGTH 150

#define POLICY_ROW_NONE    -1

// actions
#define POLICY_ACT_PASS    0x0001
#define POLICY_ACT_NAT     0x0002
#define POLICY_ACT_ENCAP   0x0003
#define POLICY_ACT_DECAP   0x0004
#define POLICY_ACT_DROP    0x0005
#define POLICY_ACT_LISP    0x0006
#define POLICY_ACT_MASK    0x000F

// operation policies
#define POLICY_OP_COMPRESS      0x0010
#define POLICY_OP_ENCRYPT       0x0020
#define POLICY_OP_DEJITTER      0x0040
#define POLICY_OP_ACCEL         0x0080
#define POLICY_OP_DUPLICATE     0x0100
#define POLICY_OP_LIMIT         0x0200
#define POLICY_OP_CODING        0x0400
#define POLICY_OP_MULTIPATH     0x0800
#define POLICY_OP_MASK          0x0FF0



enum policy_type {
    POLICY_TYPE_FLOW,
    POLICY_TYPE_DEV
};

typedef struct{
    uint32_t action;
    uint32_t direction;
    uint16_t table;
    int32_t type; //algo type
    uint16_t flags;
    // flow policy
    struct flow_tuple ft;
    uint32_t local_netmask;
    uint32_t remote_netmask;

    char dev_name[IFNAMSIZ];
    int max_rate;

    char alg_name[MAX_ALG_NAME_LEN];
}policy_entry;

int init_policy_table();

int get_policy_by_tuple(struct flow_tuple* ft,  policy_entry *policy, int dir);

//---------DEBUG METHODS------------//

void print_policy_entry(policy_entry * pe);
void print_policies();





#endif //POLICY_FUNCTIONS_H
