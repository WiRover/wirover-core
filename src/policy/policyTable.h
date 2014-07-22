/*
 * policyFunctions.h
 */

#ifndef POLICY_FUNCTIONS_H
#define POLICY_FUNCTIONS_H

#include <stdint.h>
#include "flow_table.h"

#define POLICY_TABLE_IN_FILE "policy_table_in.txt"
#define POLICY_TABLE_OUT_FILE "policy_table_out.txt"
#define INGRESS 0
#define EGRESS 1

#define SUCCESSFUL_MATCH 0
#define NO_MATCH 1
#define BAD_INPUT -1

#define MAX_ALG_NAME_LEN   16

#define MAX_POLICY_ENTRY_LENGTH 150

#define POLICY_TBL_INPUT   0x01
#define POLICY_TBL_OUTPUT  0x02

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

enum policy_command {
    POLICY_CMD_APPEND,
    POLICY_CMD_DELETE,
    POLICY_CMD_INSERT,
    POLICY_CMD_REPLACE,
    POLICY_CMD_FLUSH,  // flush a specific table
    POLICY_CMD_MAX,
};

enum policy_type {
    POLICY_TYPE_DEFAULT,
    POLICY_TYPE_FLOW,
    POLICY_TYPE_DEV,
    POLICY_TYPE_APP,
    POLICY_TYPE_MAX,
};

struct policy_entry {
    int command;
    int row;

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
    // app policy
    //char app_name[POLICY_MAX_APP_NAME];
    // dev policy
    //char dev_name[IFNAMSIZ];

    // rate limit params
    //int max_rate;

    // encrypt params
    // compression params
    // coding params

    // algo params
    char alg_name[MAX_ALG_NAME_LEN];
    //int slave_count;
    //char slave_list[3][IFNAMSIZ];
    //int slave_weight[3];

};

int appendPolicy(char *, struct policy_entry *);
int deletePolicy(char *, struct policy_entry *);
int insertPolicy(char *, struct policy_entry *);
int getMatch(struct flow_tuple*, struct policy_entry*, int);



    



#endif //POLICY_FUNCTIONS_H
