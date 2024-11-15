#include "basetype.h"
#include "errmsg.h"

typedef struct _udp_socket udp_socket;
typedef struct {
    u8 a, b, c, d;
} ip_address;
typedef struct {
    ip_address ip;
    u16 port;
} udp_address;

/* Init */
int zzmsg_init();

/* Create socket */
int zzmsg_create_socket(udp_socket *sock);

/* Send udp message */
int zzmsg_send_udp(udp_socket sock, udp_address addr, u8 *data);

/* Bind socket */
int zzmsg_bind_socket(udp_socket sock, u16 port);

/* Join multicast group */
int zzmsg_join_multicast_group(udp_socket sock, ip_address group);

/* Receive udp message */
int zzmsg_recv_udp(udp_socket sock, udp_address *addr, u8 *buf, u32 len);
