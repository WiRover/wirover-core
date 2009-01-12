/*
 * policyFunctions.h
 */

#ifndef POLICY_FUNCTIONS_H
#define POLICY_FUNCTIONS_H

#include <stdint.h>

#define POLICY_TABLE_IN_FILE "policy_table_in.txt"
#define POLICY_TABLE_OUT_FILE "policy_table_out.txt"

#define MAX_ALG_NAME_LEN   16

#define MAX_POLICY_ENTRY_LENGTH 150

struct policy_req {
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

int appendPolicy(char *, struct policy_req *);
int deletePolicy(char *, struct policy_req *);
int insertPolicy(char *, struct policy_req *);


#endif //POLICY_FUNCTIONS_H
