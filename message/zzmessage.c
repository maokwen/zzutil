#include "zzmessage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MINGW) || defined(_WIN32)
#include <Ws2tcpip.h>
#include <winsock2.h>
#elif _UNIX
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include "zzmessage.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
// #include <arpa/inet.h>
#endif

#ifdef _WIN32
IN_ADDR addr_in(u8 a, u8 b, u8 c, u8 d);
SOCKADDR_IN addrconv_zz2win(u8 a, u8 b, u8 c, u8 d, u16 port);
udp_address addrconv_win2zz(SOCKADDR_IN addr);
#endif

#ifdef _UNIX
in_addr_t ipconv_zz2unix(u8 a, u8 b, u8 c, u8 d);
struct sockaddr_in addrconv_zz2unix(u8 a, u8 b, u8 c, u8 d, u16 port);
udp_address addrconv_unix2zz(struct sockaddr_in addr);
#endif

int zzmsg_is_initilized = 0;

/* check if initialized */
int check_init();

/* Set socket reusable */
int set_socket_reusable(udp_socket sock);

/* Init */
int zzmsg_init() {
    int ret;
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        printf("WSAStartup() failed\n");
        return ZZMSG_RET_OS_ERROR;
    }
#endif
    zzmsg_is_initilized = 1;
    return ZZMSG_RET_OK;
}

/* Create socket */
int zzmsg_create_socket(udp_socket *sock) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

#ifdef _WIN32
    // create socket
    sock->sock_ptr = malloc(sizeof(SOCKET));
    *(SOCKET *)(sock->sock_ptr) = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ((int)sock->sock_ptr == INVALID_SOCKET) {
        printf("socket() failed\n");
        return ZZMSG_RET_OS_ERROR;
    }
    printf("socket() success\n");
#endif

#ifdef _UNIX
    int *psock = malloc(sizeof(int));
    *psock = socket(AF_INET, SOCK_DGRAM, 0);
    if (*psock < 0) {
        printf("socket() failed\n");
        return ZZMSG_RET_OS_ERROR;
    }
    sock->sock_ptr = (void *)psock;
#endif

    return ZZMSG_RET_OK;
}

/* Bind socket */
int zzmsg_bind_socket(udp_socket sock, u16 port) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

#ifdef _WIN32
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = set_socket_reusable(sock);
    if (ret) {
        return ret;
    }

    ret = bind(*(SOCKET *)(sock.sock_ptr), (SOCKADDR *)&addr, sizeof(SOCKADDR_IN));
    if (ret == SOCKET_ERROR) {
        printf("bind() failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

#ifdef _UNIX
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = set_socket_reusable(sock);
    if (ret) {
        printf("bind() failed, code %d\n", ret);
        return ret;
    }
#endif

    printf("bind() success\n");
    return ZZMSG_RET_OK;
}

/* join multicast group */
int zzmsg_join_multicast_group(udp_socket sock, ip_address group) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

#ifdef _WIN32
    struct ip_mreq mreq;
    mreq.imr_multiaddr = addr_in(group.a, group.b, group.c, group.d);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    ret = setsockopt(*(SOCKET *)(sock.sock_ptr), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
    if (ret) {
        printf("setsockopt() failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

#ifdef _UNIX
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = ipconv_zz2unix(group.a, group.b, group.c, group.d);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    ret = setsockopt(*(int *)(sock.sock_ptr), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
    if (ret) {
        printf("setsockopt() failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }

#endif

    printf("join multicast group success\n");
    return ZZMSG_RET_OK;
}

/* Send udp message */
int zzmsg_send_udp(udp_socket sock, udp_address addr, u8 *data, u32 len) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

#ifdef _WIN32
    SOCKADDR_IN dest = addrconv_zz2win(addr.ip.a, addr.ip.b, addr.ip.c, addr.ip.d, addr.port);
    ret = sendto(*(SOCKET *)(sock.sock_ptr), data, len, 0, (SOCKADDR *)&dest, sizeof(SOCKADDR_IN));
    if (ret == 0) {
        printf("sendto() failed\n");
        return ZZMSG_RET_OS_ERROR;
    }
#endif

#ifdef _UNIX
    struct sockaddr_in dest = addrconv_zz2unix(addr.ip.a, addr.ip.b, addr.ip.c, addr.ip.d, addr.port);
    ret = sendto(*(int *)(sock.sock_ptr), data, len, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr_in));
    if (ret == 0) {
        printf("sendto() failed\n");
        return ZZMSG_RET_OS_ERROR;
    }
#endif

    return ZZMSG_RET_OK;
}

/* Receive udp message */
int zzmsg_recv_udp(udp_socket sock, udp_address *addr, u8 *buf, u32 len, u32 *receive_len) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

#ifdef _WIN32
    SOCKADDR_IN from;
    int from_len = sizeof(SOCKADDR_IN);

    int bytes_received = recvfrom(*(SOCKET *)(sock.sock_ptr), buf, len - 1, 0, (SOCKADDR *)&from, &from_len);
    if (bytes_received <= 0) {
        printf("recvfrom() failed\n");
        return ZZMSG_RET_OS_ERROR;
    }
    if (bytes_received == len - 1) {
        printf("buffer is too small\n");
        return ZZMSG_RET_BUFFER_TOO_SMALL;
    }

    buf[bytes_received] = '\0';
    *receive_len = bytes_received + 1;
    *addr = addrconv_win2zz(from);
#endif

#ifdef _UNIX
    struct sockaddr_in from;
    int from_len = sizeof(struct sockaddr_in);
    int bytes_received = recvfrom(*(int *)(sock.sock_ptr), buf, len - 1, 0, (struct sockaddr *)&from, &from_len);
    if (bytes_received <= 0) {
        printf("recvfrom() failed\n");
        return ZZMSG_RET_OS_ERROR;
    }
    if (bytes_received == len - 1) {
        printf("buffer is too small\n");
        return ZZMSG_RET_BUFFER_TOO_SMALL;
    }

    buf[bytes_received] = '\0';
    *receive_len = bytes_received + 1;
    *addr = addrconv_unix2zz(from);
#endif

    return ZZMSG_RET_OK;
}

/* SECTION platform-specific functions */

#ifdef _WIN32

IN_ADDR addr_in(u8 a, u8 b, u8 c, u8 d) {
    IN_ADDR addr;
    addr.S_un.S_addr = htonl(a << 24 | b << 16 | c << 8 | d);
    return addr;
}

SOCKADDR_IN addrconv_zz2win(u8 a, u8 b, u8 c, u8 d, u16 port) {
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = addr_in(a, b, c, d);
    return addr;
}

udp_address addrconv_win2zz(SOCKADDR_IN addr) {
    udp_address zzaddr;
    zzaddr.ip.a = addr.sin_addr.S_un.S_un_b.s_b1;
    zzaddr.ip.b = addr.sin_addr.S_un.S_un_b.s_b2;
    zzaddr.ip.c = addr.sin_addr.S_un.S_un_b.s_b3;
    zzaddr.ip.d = addr.sin_addr.S_un.S_un_b.s_b4;
    zzaddr.port = addr.sin_port;
    return zzaddr;
}
#endif

#ifdef _UNIX

in_addr_t ipconv_zz2unix(u8 a, u8 b, u8 c, u8 d) {
    return htonl(a << 24 | b << 16 | c << 8 | d);
}

struct sockaddr_in addrconv_zz2unix(u8 a, u8 b, u8 c, u8 d, u16 port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ipconv_zz2unix(a, b, c, d);
    return addr;
}

udp_address addrconv_unix2zz(struct sockaddr_in addr) {
    udp_address zzaddr;
    zzaddr.ip.a = addr.sin_addr.s_addr >> 24;
    zzaddr.ip.b = addr.sin_addr.s_addr >> 16;
    zzaddr.ip.c = addr.sin_addr.s_addr >> 8;
    zzaddr.ip.d = addr.sin_addr.s_addr;
    zzaddr.port = addr.sin_port;
    return zzaddr;
}

#endif

/* !SECTION platform-specific functions */

int check_init() {
    if (!zzmsg_is_initilized) {
        printf("zzmsg_init() must be called first\n");
        return 1;
    }
    return 0;
}

int set_socket_reusable(udp_socket sock) {
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }
#ifdef _WIN32
    int ret = 0;
    setsockopt(*(SOCKET *)(sock.sock_ptr), SOL_SOCKET, SO_REUSEADDR, (char *)&ret, sizeof(ret));
    if (ret) {
        printf("setsockopt() failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

#ifdef _UNIX
    int ret = 0;
    int *psock = (int *)sock.sock_ptr;
    setsockopt(*(int*)(sock.sock_ptr), SOL_SOCKET, SO_REUSEADDR, (char *)&ret, sizeof(ret));
    if (ret) {
        printf("setsockopt() failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

    printf("setsockopt() success\n");
    return ZZMSG_RET_OK;
}
