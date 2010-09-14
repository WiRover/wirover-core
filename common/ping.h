#ifndef _PING_H_
#define _PING_H_

#define PING_PACKET_TYPE  0x20

struct ping_packet {
    uint32_t    seq_no;
    uint8_t     type;
    uint16_t    src_id;
    uint32_t    link_id;
    uint32_t    sent_sec;
    uint32_t    sent_usec;
} __attribute__((__packed__));

int start_ping_thread();

#ifdef GATEWAY
int ping_all_interfaces(const char* dst_ip, unsigned short dst_port, unsigned short src_port);
int send_ping(struct interface* ife, unsigned short src_port, unsigned int dest_port,
              const struct sockaddr* dest_addr, socklen_t dest_len);
#endif

#endif //_PING_H_

