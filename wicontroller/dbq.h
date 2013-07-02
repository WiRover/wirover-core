#define DBQ_LENGTH 32

typedef struct{
    char query[1040];
    int gps_req;
    int gwid;
    char hash[NODE_HASH_SIZE + 1];
}dbqreq;

void init_dbq();
int dbq_enqueue(dbqreq* req);
dbqreq* dbq_dequeue();
