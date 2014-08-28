#ifndef _UTIL_H_
#define _UTIL_H_

int add_route(__be32 dest, __be32 gateway, __be32 netmask, __be32 metric, const char *device);
int delete_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);

int read_public_key(char *buffer, int size);
int authorize_public_key(char *pub_key, int size);

#endif //_KERNEL_H_

