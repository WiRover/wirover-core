#ifndef WIROVER_VERSION_H
#define WIROVER_VERSION_H

struct wirover_version {
    unsigned char major;
    unsigned char minor;
    unsigned short revision;
} __attribute__((__packed__));

void get_wirover_version_net(struct wirover_version *dest);

#endif /* WIROVER_VERSION_H */
