#include "zzutil/zzmessage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MINGW) || defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#elif _UNIX
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include "zzmessage.h"
#include "zzutil/zzmessage.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>
// #include <arpa/inet.h>
#endif

#ifdef _WIN32
static IN_ADDR addr_in(u8 a, u8 b, u8 c, u8 d);
static SOCKADDR_IN addrconv_zz2win(u8 a, u8 b, u8 c, u8 d, u16 port);
static udp_address addrconv_win2zz(SOCKADDR_IN addr);
/* convert mac address string to mac_address */
static mac_address addrconv_win2mac(u8 *mac);
#endif

#ifdef _UNIX
static in_addr_t ipconv_zz2unix(u8 a, u8 b, u8 c, u8 d);
static struct sockaddr_in addrconv_zz2unix(u8 a, u8 b, u8 c, u8 d, u16 port);
static udp_address addrconv_unix2zz(struct sockaddr_in addr);
#endif

static int zzmsg_is_initilized = 0;
/* convert ip address string to ip_address */
static ip_address addrconv_str2ip(char *);
/* check if initialized */
static int check_init();
/* Set socket reusable */
static int set_socket_reusable(udp_socket sock);
/* Set socket interface */
static int set_socket_if(udp_socket sock, ip_address ip);

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
int zzmsg_bind_socket(udp_socket sock, u16 port, ip_address *local_ip) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

    if (local_ip) {
        ret = set_socket_if(sock, *local_ip);
        if (ret) {
            printf("bind() failed\n");
            return ZZMSG_RET_SETSOCKET_FAILED;
        }
    }

    ret = set_socket_reusable(sock);
    if (ret) {
        printf("bind() failed\n");
        return ZZMSG_RET_SETSOCKET_FAILED;
    }

#ifdef _WIN32
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

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

    ret = bind(*(int *)(sock.sock_ptr), (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (ret) {
        printf("bind() failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
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
    char ip[] = "192.168.28.189";
    mreq.imr_interface.s_addr = inet_addr(ip);
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
int zzmsg_send_udp(udp_socket sock, udp_address addr, u8 *data, u32 len, ip_address *local_ip) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

    if (local_ip) {
        ret = set_socket_if(sock, *local_ip);
        if (ret) {
            printf("send_udp() failed\n");
            return ZZMSG_RET_SETSOCKET_FAILED;
        }
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

int zzmsg_close_socket(udp_socket sock) {
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

#ifdef _WIN32
    closesocket(*(SOCKET *)(sock.sock_ptr));
    free(sock.sock_ptr);
#endif

#ifdef _UNIX
    close(*(int *)(sock.sock_ptr));
    free(sock.sock_ptr);
#endif

    return ZZMSG_RET_OK;
}

/* Get all interfaces */
int zzmsg_get_all_interfaces(adapter_info **ifs, u32 *count) {
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }

#ifdef _WIN32
    DWORD ret = 0;
    DWORD size = 0;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG family = AF_UNSPEC;

    PIP_ADAPTER_ADDRESSES addresses = NULL;

    ret = GetAdaptersAddresses(family, flags, NULL, addresses, &size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
        *ifs = (adapter_info *)malloc(size * sizeof(adapter_info));
    }

    ret = GetAdaptersAddresses(family, flags, NULL, addresses, &size);
    if (ret != NO_ERROR) {
        printf("GetAdaptersAddresses() failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }

    PIP_ADAPTER_ADDRESSES p = addresses;
    int i = 0;
    while (p) {
        (*ifs)[i].name = strdup(p->AdapterName);
        if (p->PhysicalAddressLength == 6) {
            (*ifs)[i].mac = addrconv_win2mac(p->PhysicalAddress);
        } else {
            (*ifs)[i].mac = (mac_address){0, {0}};
        }
        char **ip_list = NULL;

        // get all ip addresses
        int ip_count = 0;
        IP_ADAPTER_UNICAST_ADDRESS *pUnicast = p->FirstUnicastAddress;
        while (pUnicast) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[16];
                inet_ntop(AF_INET, &((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr, ip, 16);
                // (*ifs)[i].ip[ip_count] = addrconv_str2ip(ip);
                if (ip_count == 0) {
                    ip_list = (char **)malloc(sizeof(char *));
                } else {
                    ip_list = (char **)realloc(ip_list, (ip_count + 1) * sizeof(char *));
                }
                ip_list[ip_count] = (char *)malloc(16);
                strcpy(ip_list[ip_count], ip);
                ip_count += 1;
            }
            pUnicast = pUnicast->Next;
        }

        (*ifs)[i].ip = (ip_address *)malloc(ip_count * sizeof(ip_address));
        for (int j = 0; j < ip_count; j++) {
            (*ifs)[i].ip[j] = addrconv_str2ip(ip_list[j]);
            free(ip_list[j]);
        }
        (*ifs)[i].ip_count = ip_count;

        i += 1;
        p = p->Next;
    }

    *count = i;
    free(addresses);
#endif

#ifdef _UNIX
// TODO
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

mac_address addrconv_win2mac(u8 *mac) {
    mac_address zzmac;
    for (int i = 0; i < 6; ++i) {
        zzmac.addr[i] = mac[i];
    }
    return zzmac;
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

ip_address addrconv_str2ip(char *str) {
    ip_address ip;
    sscanf(str, "%d.%d.%d.%d", &ip.a, &ip.b, &ip.c, &ip.d);
    return ip;
}

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
        printf("setsockopt(reusable) failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

#ifdef _UNIX
    int ret = 0;
    int *psock = (int *)sock.sock_ptr;
    setsockopt(*(int *)(sock.sock_ptr), SOL_SOCKET, SO_REUSEADDR, (char *)&ret, sizeof(ret));
    if (ret) {
        printf("setsockopt(reusable) failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

    printf("setsockopt(reusable) success\n");
    return ZZMSG_RET_OK;
}

int set_socket_if(udp_socket sock, ip_address ip) {
    int ret;
    if (check_init()) {
        return ZZMSG_RET_NO_INIT;
    }
#ifdef _WIN32
    IN_ADDR addr = addr_in(ip.a, ip.b, ip.c, ip.d);
    ret = setsockopt(*(SOCKET *)(sock.sock_ptr), IPPROTO_IP, IP_MULTICAST_IF, (const char *)&addr, sizeof(addr));
    if (ret) {
        printf("setsockopt(if) failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

#ifdef _UNIX
    int *psock = (int *)sock.sock_ptr;
    in_addr_t addr = ipconv_zz2unix(ip->a, ip->b, ip->c, ip->d);
    ret = setsockopt(*(int *)(sock.sock_ptr), IPPROTO_IP, IP_MULTICAST_IF, (const char *)&addr, sizeof(addr));
    if (ret) {
        printf("setsockopt(if) failed, code %d\n", ret);
        return ZZMSG_RET_OS_ERROR;
    }
#endif

    printf("setsockopt(if) success\n");
    return ZZMSG_RET_OK;
}
