#ifndef _KERNEL_H_
#define _KERNEL_H_

#define SIOCVIRTENSLAVE   (SIOCDEVPRIVATE + 0)
#define SIOCVIRTRELEASE   (SIOCDEVPRIVATE + 1)
#define SIOCVIRTSETHWADDR (SIOCDEVPRIVATE + 2)
#define SIOCVIRTSETPROXY  (SIOCDEVPRIVATE + 3)

int setup_virtual_interface(const char* __restrict__ ip);

int kernel_set_controller(const struct sockaddr_in* addr);
int kernel_enslave_device(const char* device);
int kernel_release_device(const char* device);

#endif //_KERNEL_H_

