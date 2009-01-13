#ifndef TUNNEL_H
#define TUNNEL_H

struct tunhdr {
    __u8    flags;
    __u8    version;
    __be16  prev_len;
    __be32  send_ts;
    __be32  recv_ts;
} __attribute__((__packed__));

#define TUNFLAG_PING  0x10

#endif //TUNNEL_H

