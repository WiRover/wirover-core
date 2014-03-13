/*
 * flowTable.c
 */
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "../common/debug.h"

#include "flowTable.h"
#include "uthash.h"
#include "headerParse.h"

#define TIME_BUFFER_SIZE 1024
#define TIME_BETWEEN_EXPIRATION_CHECKS 5

struct flow_entry {
    struct flow_tuple *id;
    time_t last_visit_time;
    struct flow_table_data *ftd;
    UT_hash_handle hh;
};

struct flow_entry *flow_table = NULL;
int flow_table_timeout = 10;
time_t last_expiration_check = 0;


int add_entry(struct flow_tuple* entry, struct flow_table_data *ftd) {
    struct flow_entry *fe;

    struct flow_tuple *newKey = (struct flow_tuple *) malloc(sizeof(struct flow_tuple));
    memset(newKey, 0, sizeof(struct flow_tuple));
    memcpy(newKey, entry, sizeof(struct flow_tuple));
    HASH_FIND(hh, flow_table, newKey, sizeof(struct flow_tuple), fe);
    if(fe == NULL) {
        fe = (struct flow_entry *) malloc(sizeof(struct flow_entry));
        memset(fe, 0, sizeof(struct flow_entry));
        fe->id = newKey;
        fe->ftd = ftd;
        fe->last_visit_time = time(NULL);

        HASH_ADD_KEYPTR(hh, flow_table, newKey, sizeof(struct flow_tuple), fe);
        return SUCCESS;
    }

    free(newKey);
    return DUPLICATE_ENTRY;
}

struct flow_entry *find_entry(struct flow_tuple *entry) {
    struct flow_entry *fe;

    HASH_FIND(hh, flow_table, entry, sizeof(struct flow_tuple), fe);
    if(fe != NULL) {
        fe->last_visit_time = time(NULL);
    }

    return fe;
} 


struct flow_table_data *get_flow_data(struct flow_tuple *entry) {
    struct flow_entry *fe = find_entry(entry);
    if(fe == NULL) {
        return NULL;
    }

    return fe->ftd;
}

int update_flow_table(struct flow_tuple *entry) {
    struct flow_table_data *ftd = get_flow_data(entry);
    if(ftd == NULL) {
        ftd = (struct flow_table_data *) malloc(sizeof(struct flow_table_data));
        memset(ftd, 0, sizeof(struct flow_table_data));
        ftd->count = 1;
        int rc = add_entry(entry, ftd);
        if(rc == DUPLICATE_ENTRY) {
            DEBUG_MSG("Duplicate File error");
        }
        return rc;
    }
    ftd->count++;

    if(last_expiration_check == 0) {
        last_expiration_check = time(NULL);
    }
    if(time(NULL) - last_expiration_check > TIME_BETWEEN_EXPIRATION_CHECKS) {
        expiration_time_check();
        last_expiration_check = time(NULL);
    }

    return SUCCESS;
}

void expiration_time_check() {
    struct flow_entry *current_key, *tmp;
    record_message_to_file("outData.dat", "Starting time check");

    HASH_ITER(hh, flow_table, current_key, tmp) {
        if(time(NULL) - current_key->last_visit_time > flow_table_timeout) {
            free(current_key->ftd);
            HASH_DEL(flow_table, current_key);
            free(current_key);
        }
    }
}


int set_flow_table_timeout(int value) {
    flow_table_timeout = value;
}



//All methods below here are for debugging purposes
void print_keys(char * file_name) {
    struct flow_entry *current_key, *tmp;

    record_message_to_file(file_name, "-----STARTING KEY PRINT-----");

    FILE *ofp;
    ofp = fopen(file_name, "a");
    if (ofp == NULL) {
        ERROR_MSG("fopen() Failed");
        return FILE_ERROR;
    }

    HASH_ITER(hh, flow_table, current_key, tmp) {
            fprintf(ofp,
              "FROM: %" PRIu32 " TO: %" PRIu32 " PORTFROM: %" PRIu16 " PORTTO: %" PRIu16 ", NETPROTO: %" PRIu8 ", PROTO: %" PRIu8 "\n",
              current_key->id->sAddr, current_key->id->dAddr, current_key->id->sPort,
              current_key->id->dPort, current_key->id->net_proto, current_key->id->proto
            );
    }

    fclose(ofp);
    record_message_to_file(file_name, "-----ENDING   KEY PRINT-----");
}


int record_message_to_file(char * file_name, char * msg) {
    FILE *ofp;
    ofp = fopen(file_name, "a");
    if (ofp == NULL) {
        ERROR_MSG("fopen() Failed");
        return FILE_ERROR;
    }

    struct timeval now;
    struct tm nowTm;

    gettimeofday(&now, NULL);
    localtime_r(&now.tv_sec, &nowTm);

    char buff[MAX_DEBUG_LEN];
    char *pbuff = buff;

    snprintf(pbuff, sizeof(buff), "%02d/%02d/%04d %02d:%02d:%02d.%06d",
            nowTm.tm_mon + 1, nowTm.tm_mday, nowTm.tm_year + 1900,
            nowTm.tm_hour, nowTm.tm_min, nowTm.tm_sec, (int)now.tv_usec);

    fprintf(ofp, "%s -- %d -- MSG: %s\n", pbuff, getpid(), msg);

    fclose(ofp);

    return SUCCESS;
}


int record_data_to_file(char * file_name, 
                        struct flow_tuple *ft, struct flow_table_data *ftd) {
    FILE *ofp;
    ofp = fopen(file_name, "a");
    if (ofp == NULL) {
        ERROR_MSG("fopen() Failed");
        return FILE_ERROR;
    }

    struct timeval now;
    struct tm nowTm;

    gettimeofday(&now, NULL);
    localtime_r(&now.tv_sec, &nowTm);

    char buff[MAX_DEBUG_LEN];
    char *pbuff = buff;

    snprintf(pbuff, sizeof(buff), "%02d/%02d/%04d %02d:%02d:%02d.%06d",
            nowTm.tm_mon + 1, nowTm.tm_mday, nowTm.tm_year + 1900,
            nowTm.tm_hour, nowTm.tm_min, nowTm.tm_sec, (int)now.tv_usec);

    char *sAddrString;
    char *dAddrString;

    sAddrString = inet_ntoa(*(struct in_addr*)&ft->sAddr);
    dAddrString = inet_ntoa(*(struct in_addr*)&ft->dAddr);

    /*fprintf(ofp, "%s -- THE COUNT IS: %d FROM: %" PRIu32 " TO: %" PRIu32 " PORTFROM: %" PRIu16 " PORTTO: %" PRIu16 ", NETPROTO: %" PRIu8 ", PROTO: %" PRIu8 "\n",
            pbuff, ftd->count, ft->sAddr, ft->dAddr, ft->sPort, ft->dPort, ft->net_proto, ft->proto);*/

    fprintf(ofp, "%s -- THE COUNT IS: %d FROM: %s TO: %s PORTFROM: %" PRIu16 " PORTTO: %" PRIu16 " NETPROTO: %" PRIu8 " PROTO: %" PRIu8 "\n",
            pbuff, ftd->count, sAddrString, dAddrString, ft->sPort, ft->dPort, ft->net_proto, ft->proto);

    fclose(ofp);

    return SUCCESS;
}
