#ifndef _PING_H_
#define _PING_H_

#define PING_PACKET_TYPE    0x20

#define USEC_PER_SEC        1000000

struct ping_packet {
    uint32_t    seq_no;
    uint8_t     type;
    int8_t      link_state;
    uint16_t    src_id;
    uint16_t    link_id;
    uint32_t    sent_sec;
    uint32_t    sent_usec;
} __attribute__((__packed__));

#define PING_PACKET_SIZE (sizeof(struct tunhdr) + sizeof(struct ping_packet))

int start_ping_thread();

#ifdef GATEWAY
int ping_all_interfaces(unsigned short src_port);
int ping_interface(struct interface* ife);
#endif

#endif //_PING_H_

