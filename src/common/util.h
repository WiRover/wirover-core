#ifndef _UTIL_H_
#define _UTIL_H_

int add_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);
int delete_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);

#endif //_KERNEL_H_

