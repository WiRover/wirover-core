#ifndef TUNNEL_H
#define TUNNEL_H

struct tunhdr {
    __u8    flags;
    __u8    __padding0;
    __be16  prev_len;
    __be32  send_ts;
    __be32  recv_ts;
} __attribute__((__packed__));

#define TUNFLAG_DONT_DECAP  0x10  /* Pass the packet up to the user level. */

#endif //TUNNEL_H

