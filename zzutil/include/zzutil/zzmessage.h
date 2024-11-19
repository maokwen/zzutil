#ifndef ZZUTIL_ZZMESSAGE_H
#define ZZUTIL_ZZMESSAGE_H

#include "basetype.h"
#include "errmsg.h"

typedef struct _udp_socket udp_socket;
typedef struct _mac_address mac_address;
typedef struct _ip_address ip_address;
typedef struct _udp_address udp_address;
typedef struct _adapter_info {
    char *name;
    mac_address mac;
    ip_address *ip;
    int ip_count;
} adapter_info;

/* Init */
int zzmsg_init();

/* Create socket */
int zzmsg_create_socket(udp_socket *sock);

/* Send udp message */
int zzmsg_send_udp(udp_socket sock, udp_address addr, u8 *data, u32 len, ip_address *local_ip);

/* Bind socket */
int zzmsg_bind_socket(udp_socket sock, u16 port, ip_address *local_ip);

/* Join multicast group */
int zzmsg_join_multicast_group(udp_socket sock, ip_address group);

/* Receive udp message */
int zzmsg_recv_udp(udp_socket sock, udp_address *addr, u8 *buf, u32 len, u32 *recv_len);

/* Close socket */
int zzmsg_close_socket(udp_socket sock);

/* Get all interfaces */
int zzmsg_get_all_interfaces(adapter_info **ifs, u32 *count);

#endif // ZZUTIL_ZZMESSAGE_H
