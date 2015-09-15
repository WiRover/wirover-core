#ifndef WIROVER_VERSION_H
#define WIROVER_VERSION_H

struct wirover_version {
    uint8_t major;
    uint8_t minor;
    uint8_t revision;
} __attribute__((__packed__));

struct wirover_version get_wirover_version();
int compare_wirover_version(struct wirover_version comp);

#endif /* WIROVER_VERSION_H */
