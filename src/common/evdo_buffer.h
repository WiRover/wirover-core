/*
 *  E V D O _ B U F F E R . H
 */

#ifndef BUFFER_H
#define BUFFER_H

struct buffer_node {
	struct buffer_node *next;
	struct buffer_node *prev;

	int fd;
	char *data;
	int size;
	int flags;
	struct sockaddr *addr;
	int size_addr;
};


int createSenderThread(struct interface *head, int num_ifs);
int destroySenderThread(struct interface *head, int num_ifs);
int mySendto(int fd, char *data, int size, int flags, struct sockaddr *addr, int size_addr, struct interface *ife);
int myWrite(int fd, char *data, int size, struct interface *ife);
void *bufferThreadFunc(void *arg);

#endif
