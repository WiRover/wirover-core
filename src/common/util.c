#include <netdb.h>
//#include <stropts.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/route.h>
#include <net/if.h>

#include "debug.h"
#include "tunnel.h"
#include "util.h"

int add_route(__be32 dest, __be32 gateway, __be32 netmask, __be32 metric, const char *device)
{
    struct rtentry rt;
    char dev_buf[IFNAMSIZ];

    memset(&rt, 0, sizeof(rt));
    memset(dev_buf, 0, sizeof(dev_buf));

    rt.rt_flags = RTF_UP;

    rt.rt_dst.sa_family = AF_INET;
    struct in_addr *addr_dst = &((struct sockaddr_in *)&rt.rt_dst)->sin_addr;
    addr_dst->s_addr = dest;

    rt.rt_genmask.sa_family = AF_INET;
    struct in_addr *netmask_dst = &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr;
    netmask_dst->s_addr = netmask;
    rt.rt_metric = metric;

    if(gateway) {
        rt.rt_flags |= RTF_GATEWAY;

        rt.rt_gateway.sa_family = AF_INET;
        struct in_addr *gw_dst = &((struct sockaddr_in *)&rt.rt_gateway)->sin_addr;
        gw_dst->s_addr = gateway;
    }
    else if(dest){
        rt.rt_flags |= RTF_HOST;
    }

    if(device) {
        strncpy(dev_buf, device, sizeof(dev_buf));
        rt.rt_dev = dev_buf;
    }

    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd < 0) {
        ERROR_MSG("creating socket failed");
        return -errno;
    }

    int rtn = ioctl(skfd, SIOCADDRT, &rt);
    if(rtn == -1) {
        if(errno != EEXIST)
            ERROR_MSG("ioctl SIOCADDRT failed");

        close(skfd);
        return -errno;
    }

    close(skfd);
    return 0;
}

int delete_route(__be32 dest, __be32 gateway, __be32 netmask, const char *device)
{
    struct rtentry rt;
    char dev_buf[IFNAMSIZ];

    memset(&rt, 0, sizeof(rt));
    memset(dev_buf, 0, sizeof(dev_buf));

    rt.rt_dst.sa_family = AF_INET;
    struct in_addr *addr_dst = &((struct sockaddr_in *)&rt.rt_dst)->sin_addr;
    addr_dst->s_addr = dest;

    rt.rt_genmask.sa_family = AF_INET;
    struct in_addr *netmask_dst = &((struct sockaddr_in *)&rt.rt_genmask)->sin_addr;
    netmask_dst->s_addr = netmask;

    if(gateway) {
        rt.rt_flags |= RTF_GATEWAY;

        rt.rt_gateway.sa_family = AF_INET;
        struct in_addr *gw_dst = &((struct sockaddr_in *)&rt.rt_gateway)->sin_addr;
        gw_dst->s_addr = gateway;
    }

    if(device) {
        strncpy(dev_buf, device, sizeof(dev_buf));
        rt.rt_dev = dev_buf;
    }

    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skfd < 0) {
        ERROR_MSG("creating socket failed");
        return -errno;
    }

    int rtn = ioctl(skfd, SIOCDELRT, &rt);
    if(rtn == -1) {
        ERROR_MSG("ioctl SIOCDELRT failed");
        close(skfd);
        return -errno;
    }

    close(skfd);
    return 0;
}

int read_public_key(char *buffer, int size)
{
    FILE *fp = fopen("/home/wirover/.ssh/id_rsa.pub", "r");
    if(fp == NULL)
        return FAILURE;
    buffer = fgets(buffer, size, fp);
    char *stripped = strtok(buffer, "\n");
    memcpy(buffer, stripped, size);
    fclose(fp);
    if(buffer == NULL)
        return FAILURE;
    return strlen(buffer);
}
int authorize_public_key(char *pub_key, int size)
{
    FILE *fp = fopen("/home/wirover/.ssh/authorized_keys", "a+");
    if(fp == NULL)
        return FAILURE;
    char buffer[BUFSIZ];
    int pub_key_already_authed = 0;
    while (fgets(buffer, BUFSIZ, fp))
    {
        char *stripped = strtok(buffer, "\n");
        memcpy(buffer, stripped, size);
        if(strcmp(buffer, pub_key) == 0){
            pub_key_already_authed = 1;
            break;
        }
    }
    if(pub_key_already_authed){
        DEBUG_MSG("Pub key is already contained");
        fclose(fp);
        return SUCCESS;
    }
    DEBUG_MSG("Adding public key");
    fprintf(fp, "%s\n",pub_key);
    fclose(fp);
    return SUCCESS;
}