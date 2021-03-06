#ifndef _UTIL_H_
#define _UTIL_H_

int add_route(__be32 dest, __be32 gateway, __be32 netmask, __be32 metric, const char *device);
int delete_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device);

int drop_tcp_rst(char *device);
int remove_drop_tcp_rst(char *device);
int tcp_mtu_clamp();
int remove_tcp_mtu_clamp();
int masquerade(char *device);
int remove_masquerade(char *device);

int read_public_key(char *buffer, int size);
int authorize_public_key(char *pub_key, int size);

#endif //_KERNEL_H_

