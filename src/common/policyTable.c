#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "config.h"
#include "policyTable.h"
#include "flow_table.h"
#include "debug.h"

int insertPolicy(int dir, struct policy_entry *pr) {
   

    return 0;
}

int deletePolicy(int dir, struct policy_entry *pr) {
    

    return 0;
}

int appendPolicy(int dir, struct policy_entry *pr) {
    

    return 0;
}

int get_policy_by_tuple(struct flow_tuple *ft, struct policy_entry *pd, int dir) {
    FILE *table;
    
    return NO_MATCH;
}

int get_policy_by_index(int index, struct policy_entry *policy, int dir) {


    return index;
}
