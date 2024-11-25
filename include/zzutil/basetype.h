#ifndef ZZUTIL_BASETYPE_H
#define ZZUTIL_BASETYPE_H

#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// FIXME
struct _udp_socket {
    void *sock_ptr;
};

struct _mac_address {
    u8 is_valid;
    u8 addr[6];
};

struct _ip_address {
    u8 a, b, c, d;
};

struct _udp_address {
    struct _ip_address ip;
    u16 port;
};

/* convert ip addrress to string */
char *ip2str(struct _ip_address ip);

/* convert udp address to string */
char *udp2str(struct _udp_address addr);

#endif // ZZUTIL_BASETYPE_H
