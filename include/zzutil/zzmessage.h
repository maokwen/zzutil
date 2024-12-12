#ifndef ZZUTIL_ZZMESSAGE_H
#define ZZUTIL_ZZMESSAGE_H

#include <stdint.h>
#include "errmsg.h"

struct _zzmsg_udp_socket;

struct _zzmsg_mac_address {
    uint8_t is_valid;
    uint8_t addr[6];
};
struct _zzmsg_ip_address {
    uint8_t a, b, c, d;
};
struct _zzmsg_udp_address {
    struct _zzmsg_ip_address ip;
    uint16_t port;
};
struct _zzmsg_adapter_info {
    char *name;
    struct _zzmsg_mac_address mac;
    struct _zzmsg_ip_address *ip;
    int ip_count;
};

typedef struct _zzmsg_udp_socket zz_udp_socket_t;
typedef struct _zzmsg_mac_address zz_mac_address_t;
typedef struct _zzmsg_ip_address zz_ip_address_t;
typedef struct _zzmsg_udp_address zz_udp_address_t;
typedef struct _zzmsg_adapter_info zz_adapter_info_t;

/* Init */
int zzmsg_init();

/* Create socket */
int zzmsg_create_socket(zz_udp_socket_t **sock);

/* Send udp message */
int zzmsg_send_udp(const zz_udp_socket_t *sock, zz_udp_address_t addr, const uint8_t *data, uint32_t len, zz_ip_address_t *local_ip);

/* Bind socket */
int zzmsg_bind_socket(const zz_udp_socket_t *sock, uint16_t port, zz_ip_address_t *local_ip);

/* Join multicast group */
int zzmsg_join_multicast_group(const zz_udp_socket_t *sock, zz_ip_address_t group);

/* Receive udp message */
int zzmsg_recv_udp(const zz_udp_socket_t *sock, zz_udp_address_t *addr, uint8_t *buf, uint32_t len, uint32_t *recv_len);

/* Close socket */
int zzmsg_close_socket(zz_udp_socket_t *sock);

/* Get all interfaces */
int zzmsg_get_all_interfaces(zz_adapter_info_t **ifs, uint32_t *count);

/* convert ip addrress to string */
char *zzmsg_ip2str(zz_ip_address_t ip);

/* convert udp address to string */
char *zzmsg_udp2str(zz_udp_address_t addr);

#endif // ZZUTIL_ZZMESSAGE_H
