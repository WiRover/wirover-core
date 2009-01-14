#ifndef TUNNEL_H
#define TUNNEL_H

struct tunhdr {
    __u8    flags;
    __u8    version;
    __be16  prev_len;

    __be32  seq;
    __be32  __pad1;
    __be32  path_ack;

    __be32  send_ts;
    __be32  recv_ts;

    uint16_t   link_id;

    //uint32_t   seq_no;
    //uint32_t   service;
    //uint16_t   client_id;
    //uint16_t   node_id;
    //uint16_t   local_seq_no;
} __attribute__((__packed__));

#define TUNHDR_NO_TIMESTAMP 0xFFFFFFFF
#define TUNNEL_LATENCY_INVALID 0xFFFFFFFF

#define TUNFLAG_PING  0x10

#endif //TUNNEL_H

