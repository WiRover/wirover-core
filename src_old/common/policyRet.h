#ifndef POLICY_RET_H
#define POLICY_RET_H

#include <stdint.h>

#include "headerParse.h"

#define IN_DIR 0
#define OUT_DIR 1

#define SUCCESSFUL_MATCH 0
#define NO_MATCH 1
#define BAD_INPUT -1

#define MAX_ALG_NAME_LEN  16

struct policy_data {
    uint32_t action;
    int32_t type;
    char alg_name[MAX_ALG_NAME_LEN];
};
    

int getMatch(struct flow_tuple*, struct policy_data*, int);


#endif //POLICY_RET_H
