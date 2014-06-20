#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "policyFunctions.h"

int insertPolicy(char *tbl_name, struct policy_req *pr) {
    FILE *tmpTable;
    FILE *table;
    int isInserted = 0;
    int row = pr->row;

    char line[MAX_POLICY_ENTRY_LENGTH];

    table = fopen(tbl_name, "rt");
    tmpTable = fopen("tmpTableCpy.tmp", "w");
    while(fgets(line, MAX_POLICY_ENTRY_LENGTH, table) != NULL) {
        row--;
        if(row == 0) {
            isInserted = 1;
            fprintf(tmpTable, "%"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32" %"PRIu16" %"PRIu16" %"PRIu16" %"PRId32" %"PRIu32" %s\n", pr->src_addr, pr->src_netmask, pr->dst_addr, pr->dst_netmask, pr->src_port, pr->dst_port, pr->proto, pr->type, pr->action, pr->alg_name);
        }
        fprintf(tmpTable, "%s", line);
    }
    if(isInserted == 0) {
        fprintf(tmpTable, "%"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32" %"PRIu16" %"PRIu16" %"PRIu16" %"PRId32" %"PRIu32" %s\n", pr->src_addr, pr->src_netmask, pr->dst_addr, pr->dst_netmask, pr->src_port, pr->dst_port, pr->proto, pr->type, pr->action, pr->alg_name);
    }
    fclose(tmpTable);
    fclose(table);
    rename("tmpTableCpy.tmp", tbl_name);

    return 0;
}

int deletePolicy(char *tbl_name, struct policy_req *pr) {
    char buff[MAX_POLICY_ENTRY_LENGTH];
    char line[MAX_POLICY_ENTRY_LENGTH];

    char *pbuff = buff;
    snprintf(pbuff, sizeof(buff), "%"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32" %"PRIu16" %"PRIu16" %"PRIu16" %"PRId32" %"PRIu32" %s\n", pr->src_addr, pr->src_netmask, pr->dst_addr, pr->dst_netmask, pr->src_port, pr->dst_port, pr->proto, pr->type, pr->action, pr->alg_name);

    FILE *tmpTable;
    FILE *table;

    table = fopen(tbl_name, "rt");
    tmpTable = fopen("tmpTableCpy.tmp", "w");
    printf("BUFF - %s", buff);
    while(fgets(line, MAX_POLICY_ENTRY_LENGTH, table) != NULL) {
        printf("LINE - %s", line);
        if(strcmp(buff, line) != 0) {
            fprintf(tmpTable, "%s", line);
        }
    }
    fclose(tmpTable);
    fclose(table);
    rename("tmpTableCpy.tmp", tbl_name);

    return 0;
}

int appendPolicy(char *tbl_name, struct policy_req *pr) {
    printf("IN APPEND");
    FILE *ptf;
    ptf = fopen(tbl_name, "a");
    if (ptf == NULL) {
        printf("Can not open table - append Policy\n");
        return -1;
    }

    fprintf(ptf, "%"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32" %"PRIu16" %"PRIu16" %"PRIu16" %"PRId32" %"PRIu32" %s\n", pr->src_addr, pr->src_netmask, pr->dst_addr, pr->dst_netmask, pr->src_port, pr->dst_port, pr->proto, pr->type, pr->action, pr->alg_name);

    fclose(ptf);

    return 0;
}
