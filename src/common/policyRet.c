#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "policyRet.h"
#include "headerParse.h"
#include "policy/policyFunctions.h"
#include "debug.h"


int getMatch(struct flow_tuple *ft, struct policy_data *pd, int dir) {
    FILE *table;
    char line[MAX_POLICY_ENTRY_LENGTH];
    char *token;

    if(dir == IN_DIR) {    
        table = fopen("../common/policy/" POLICY_TABLE_IN_FILE, "rt");
        if(table == NULL) {
            DEBUG_MSG("NO INPUT POLICY TABLE\n");
            goto DEFAULT;
        }
    }
    else if(dir == OUT_DIR) {
        table = fopen("../common/policy/" POLICY_TABLE_OUT_FILE, "r");
        if(table == NULL) {
            DEBUG_MSG("NO OUTPUT POLICY TABLE");
            goto DEFAULT;
        }
    }
    else {
        return BAD_INPUT;
    }
    while(fgets(line, MAX_POLICY_ENTRY_LENGTH, table) != NULL) {
        token = strtok(line, " ");
        int curNum = atoi(token);
        if(curNum != 0 && curNum != ft->sAddr) {
            continue;
        }
        token = strtok(NULL, " ");
        token = strtok(NULL, " ");
        curNum = atoi(token);
        if(curNum != 0 && curNum != ft->dAddr) {
            continue;
        }
        token = strtok(NULL, " ");
        token = strtok(NULL, " ");
        curNum = atoi(token);
        if(curNum != 0 && curNum != ft->sPort) {
            continue;
        }
        token = strtok(NULL, " ");
        curNum = atoi(token);
        if(curNum != 0 && curNum != ft->dPort) {
            continue;
        }
        token = strtok(NULL, " ");
        curNum = atoi(token);
        if(curNum != 0 && curNum != ft->proto) {
            continue;
        }
        token = strtok(NULL, " ");
        curNum = atoi(token);
        pd->type = curNum;
        token = strtok(NULL, " ");
        curNum = atoi(token);
        pd->action = curNum;
        token = strtok(NULL, " ");
        strcpy(pd->alg_name, token);
        
        fclose(table);
        return SUCCESSFUL_MATCH;
    }

DEFAULT:
    pd->type = 0;
    pd->action = 0;
    strcpy(pd->alg_name, "def");
    fclose(table);
    return NO_MATCH;
}
