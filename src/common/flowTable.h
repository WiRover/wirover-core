/*
 * flowTable.h
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "uthash.h"
#include "headerParse.h"
#include "policyRet.h"

#define SUCCESS 0
#define DUPLICATE_ENTRY 1
#define FILE_ERROR 2

#define MAX_ALG_NAME_LEN   16

//Remove type?
struct flow_table_data {
    int count;
    uint32_t action;
    int32_t type;
    char alg_name[MAX_ALG_NAME_LEN];
};


struct flow_table_data *get_flow_data(struct flow_tuple *);

int update_flow_table(struct flow_tuple *, struct policy_data *);

int set_flow_table_timeout(int);

//Debug Methods
int record_data_to_file(char *, struct flow_tuple *, struct flow_table_data *);

int record_message_to_file(char *, char *);

int print_keys(char *);

#endif //FLOW_TABLE_H

