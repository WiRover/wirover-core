/*
 * policyFunctions.h
 */

#ifndef POLICY_FUNCTIONS_H
#define POLICY_FUNCTIONS_H

#include <stdint.h>
#include "flow_table.h"

#define INGRESS 0
#define EGRESS 1

#define SUCCESSFUL_MATCH 0
#define NO_MATCH 1
#define BAD_INPUT -1

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
    POLICY_TYPE_DEFAULT,
    POLICY_TYPE_FLOW,
    POLICY_TYPE_DEV,
    POLICY_TYPE_APP,
    POLICY_TYPE_MAX,
};

struct policy_entry {
    uint32_t action;
    uint16_t table;
    int32_t type; //algo type
    // flow policy
    uint16_t net_proto;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t src_netmask;
    uint32_t dst_netmask;
    uint16_t proto;
    uint16_t src_port;
    uint16_t dst_port;

    char dev_name[IFNAMSIZ];
    int max_rate;

    char alg_name[MAX_ALG_NAME_LEN];
};

int appendPolicy(int dir, struct policy_entry *policy);
int deletePolicy(int dir, struct policy_entry *policy);
int insertPolicy(int dir, struct policy_entry *policy);
int flushTable(int dir);

int get_policy_by_tuple(struct flow_tuple* ft, struct policy_entry *policy, int dir);
int get_policy_by_index(int index, struct policy_entry *policy, int dir);



    



#endif //POLICY_FUNCTIONS_H
