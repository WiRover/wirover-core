#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include "dbq.h"
#include "debug.h"
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static sem_t* q_entries;
static int q_head = 0;
static int q_tail = 0;
static dbqreq* q_queue[DBQ_LENGTH];
void init_dbq(){
	q_head = 0;
	q_tail = DBQ_LENGTH-1;
        q_entries = (sem_t*)malloc(sizeof(sem_t));
        sem_init(q_entries,0,0);
}
int dbq_enqueue(dbqreq* req){
	pthread_mutex_lock(&queue_lock);
        int output = 0;
	int q_count;
	sem_getvalue(q_entries,&q_count);
	if(q_count == DBQ_LENGTH){ goto unlock_return; }
	q_tail = (q_tail+1)%32;
        sem_post(q_entries);
	q_queue[q_tail] = req;
        output = 1;
unlock_return:
        pthread_mutex_unlock(&queue_lock);
	return output;
}
dbqreq* dbq_dequeue(){
        sem_wait(q_entries);
	pthread_mutex_lock(&queue_lock);
        dbqreq* out = 0;
	out = q_queue[q_head];
	q_head = (q_head+1)%DBQ_LENGTH;
        pthread_mutex_unlock(&queue_lock);
	return out;
}
/*void write(){
  char* s = (char*)malloc(sizeof(char)*1024);
  strcpy(s,"FAFF");
  dbqreq* req = (dbqreq*)malloc(sizeof(dbqreq));
  req->query = s;
  int i;
  for(i=0;i<100;i++){
    dbq_enqueue(req);
  }
}
void read(){
  dbqreq* req;
  int i;
  while(1){
    req = dbq_dequeue();
  }
}
int main(){
  pthread_t thread1;
  pthread_t thread2;
  init_dbq();
  pthread_create(&thread1, 0, &write,0);
  pthread_create(&thread2, 0, &read,0);
  pthread_join(thread2,0);
}*/
