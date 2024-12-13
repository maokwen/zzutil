#include "zzutil/zzmessage.h"
#include "common/helper.h"

#include <zzutil/errmsg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MINGW) || defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif
#ifdef _UNIX
#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netpacket/packet.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct _zzmsg_udp_socket {
#ifdef _WIN32
    void *sock_ptr;
#endif
#ifdef _UNIX
    void *sock_ptr;
#endif
};

typedef struct _zzmsg_udp_socket udp_socket;
typedef struct _zzmsg_ip_address ip_addr;
typedef struct _zzmsg_mac_address mac_addr;
typedef struct _zzmsg_udp_address udp_addr;
typedef struct _zzmsg_adapter_info adapter_info;

#ifdef _WIN32
static IN_ADDR ipconv_zz2win(u8 a, u8 b, u8 c, u8 d);
static SOCKADDR_IN addrconv_zz2win(u8 a, u8 b, u8 c, u8 d, u16 port);
static udp_addr addrconv_win2zz(SOCKADDR_IN addr);
/* convert mac address string to mac_addr */
static mac_addr addrconv_win2mac(u8 *mac);
#endif

#ifdef _UNIX
static in_addr_t ipconv_zz2unix(u8 a, u8 b, u8 c, u8 d);
static struct sockaddr_in addrconv_zz2unix(u8 a, u8 b, u8 c, u8 d, u16 port);
static udp_addr addrconv_unix2zz(struct sockaddr_in addr);
static mac_addr macconv_unix2zz(struct sockaddr_ll *addr);
static ip_addr ipconv_unix2zz(struct sockaddr_in *addr);
#endif

static int zzmsg_is_initilized = 0;
/* convert ip address string to ip_addr */
static ip_addr addrconv_str2ip(char *);
/* check if initialized */
static int check_init();
/* Set socket reusable */
static int set_socket_reusable(const udp_socket *sock);
/* Set socket interface */
static int set_socket_if(const udp_socket *sock, ip_addr ip);

/* Init */
int zzmsg_init() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        printf("WSAStartup() failed\n");
        return ZZECODE_OS_ERROR;
    }
#endif
    zzmsg_is_initilized = 1;
    return ZZECODE_OK;
}

/* Create socket */
int zzmsg_create_socket(udp_socket **sock) {
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }
    *sock = malloc(sizeof(udp_socket));
    if (!*sock) {
        return ZZECODE_OS_ERROR;
    }
    udp_socket *s = *sock;

#ifdef _WIN32
    // create socket
    s->sock_ptr = malloc(sizeof(SOCKET));
    *(SOCKET *)(s->sock_ptr) = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*(SOCKET *)(s->sock_ptr) == INVALID_SOCKET) {
        printf("socket() failed\n");
        return ZZECODE_OS_ERROR;
    }
    printf("socket() success\n");
#endif

#ifdef _UNIX
    int *psock = malloc(sizeof(int));
    *psock = socket(AF_INET, SOCK_DGRAM, 0);
    if (*psock < 0) {
        printf("socket() failed\n");
        return ZZECODE_OS_ERROR;
    }
    s->sock_ptr = (void *)psock;
#endif

    return ZZECODE_OK;
}

/* Bind socket */
int zzmsg_bind_socket(const udp_socket *sock, u16 port, ip_addr *local_ip) {
    int ret;
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }

    if (local_ip) {
        ret = set_socket_if(sock, *local_ip);
        if (ret) {
            printf("bind() failed\n");
            return ZZECODE_SETSOCKET_FAILED;
        }
    }

    ret = set_socket_reusable(sock);
    if (ret) {
        printf("bind() failed\n");
        return ZZECODE_SETSOCKET_FAILED;
    }

#ifdef _WIN32
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = bind(*(SOCKET *)(sock->sock_ptr), (SOCKADDR *)&addr, sizeof(SOCKADDR_IN));
    if (ret == SOCKET_ERROR) {
        printf("bind() failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

#ifdef _UNIX
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = bind(*(int *)(sock->sock_ptr), (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (ret) {
        printf("bind() failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

    printf("bind() success\n");
    return ZZECODE_OK;
}

/* join multicast group */
int zzmsg_join_multicast_group(const udp_socket *sock, ip_addr group) {
    int ret;
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }

#ifdef _WIN32
    struct ip_mreq mreq;
    mreq.imr_multiaddr = ipconv_zz2win(group.a, group.b, group.c, group.d);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    ret = setsockopt(*(SOCKET *)(sock->sock_ptr), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
    if (ret) {
        printf("setsockopt() failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

#ifdef _UNIX
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = ipconv_zz2unix(group.a, group.b, group.c, group.d);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    ret = setsockopt(*(int *)(sock->sock_ptr), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
    if (ret) {
        printf("setsockopt() failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

    printf("join multicast group success\n");
    return ZZECODE_OK;
}

/* Send udp message */
int zzmsg_send_udp(const udp_socket *sock, udp_addr addr, const u8 *data, u32 len, ip_addr *local_ip) {
    int ret;
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }

    if (local_ip) {
        ret = set_socket_if(sock, *local_ip);
        if (ret) {
            printf("send_udp() failed\n");
            return ZZECODE_SETSOCKET_FAILED;
        }
    }

#ifdef _WIN32
    SOCKADDR_IN dest = addrconv_zz2win(addr.ip.a, addr.ip.b, addr.ip.c, addr.ip.d, addr.port);
    ret = sendto(*(SOCKET *)(sock->sock_ptr), data, len, 0, (SOCKADDR *)&dest, sizeof(SOCKADDR_IN));
    if (ret == 0) {
        printf("sendto() failed\n");
        return ZZECODE_OS_ERROR;
    }
#endif

#ifdef _UNIX
    struct sockaddr_in dest = addrconv_zz2unix(addr.ip.a, addr.ip.b, addr.ip.c, addr.ip.d, addr.port);
    ret = sendto(*(int *)(sock->sock_ptr), data, len, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr_in));
    if (ret == 0) {
        printf("sendto() failed\n");
        return ZZECODE_OS_ERROR;
    }
#endif

    return ZZECODE_OK;
}

/* Receive udp message */
int zzmsg_recv_udp(const udp_socket *sock, udp_addr *addr, u8 *buf, u32 len, u32 *receive_len) {
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }

#ifdef _WIN32
    SOCKADDR_IN from;
    int from_len = sizeof(SOCKADDR_IN);

    int bytes_received = recvfrom(*(SOCKET *)(sock->sock_ptr), buf, len - 1, 0, (SOCKADDR *)&from, &from_len);
    if (bytes_received <= 0) {
        printf("recvfrom() failed\n");
        return ZZECODE_OS_ERROR;
    }
    if (bytes_received == len - 1) {
        printf("buffer is too small\n");
        return ZZECODE_BUFFER_TOO_SMALL;
    }

    buf[bytes_received] = '\0';
    *receive_len = bytes_received + 1;
    *addr = addrconv_win2zz(from);
#endif

#ifdef _UNIX
    struct sockaddr_in from;
    int from_len = sizeof(struct sockaddr_in);
    int bytes_received = recvfrom(*(int *)(sock->sock_ptr), buf, len - 1, 0, (struct sockaddr *)&from, &from_len);
    if (bytes_received <= 0) {
        printf("recvfrom() failed\n");
        return ZZECODE_OS_ERROR;
    }
    if (bytes_received == len - 1) {
        printf("buffer is too small\n");
        return ZZECODE_BUFFER_TOO_SMALL;
    }

    buf[bytes_received] = '\0';
    *receive_len = bytes_received + 1;
    *addr = addrconv_unix2zz(from);
#endif

    return ZZECODE_OK;
}

int zzmsg_close_socket(udp_socket *sock) {
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }

#ifdef _WIN32
    closesocket(*(SOCKET *)(sock->sock_ptr));
    free(sock->sock_ptr);
    sock->sock_ptr = NULL;
#endif

#ifdef _UNIX
    close(*(int *)(sock->sock_ptr));
    free(sock->sock_ptr);
    sock->sock_ptr = NULL;
#endif

    return ZZECODE_OK;
}

/* Get all interfaces */
int zzmsg_get_all_interfaces(adapter_info **ifs, u32 *count) {
    if (check_init()) {
        return ZZECODE_NO_INIT;
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
        return ZZECODE_OS_ERROR;
    }

    PIP_ADAPTER_ADDRESSES p = addresses;
    int i = 0;
    while (p) {
        (*ifs)[i].name = strdup(p->AdapterName);
        if (p->PhysicalAddressLength == 6) {
            (*ifs)[i].mac = addrconv_win2mac(p->PhysicalAddress);
        } else {
            (*ifs)[i].mac = (mac_addr){0, {0}};
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

        (*ifs)[i].ip = (ip_addr *)malloc(ip_count * sizeof(ip_addr));
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
    int ret;
    struct ifaddrs *ifaddr, *ifa;
    ret = getifaddrs(&ifaddr);
    if (ret) {
        printf("getifaddrs() failed\n");
        return ZZECODE_OS_ERROR;
    }

    int found;
    int ifname_count = 0;
    int mapIfIndex[100];
    char **ifname_list = (char **)malloc(100 * sizeof(char *));
    ip_addr *ip_list = (ip_addr *)malloc(100 * sizeof(ip_addr));
    mac_addr *mac_list = (mac_addr *)malloc(100 * sizeof(mac_addr));
    memset(mapIfIndex, -1, sizeof(mapIfIndex));

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            // TODO: drop gateway address
            // record interface name & ip address
            found = 0;
            for (int i = 0; i <= ifname_count; i++) {
                if (strcmp(ifa->ifa_name, ifname_list[i]) == 0) {
                    mapIfIndex[ifname_count] = i;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                mapIfIndex[ifname_count] = ifname_count;
            }
            ifname_list[ifname_count] = strdup(ifa->ifa_name);
            ip_list[ifname_count] = ipconv_unix2zz((struct sockaddr_in *)ifa->ifa_addr);
            ifname_count += 1;
        } else if (ifa->ifa_addr->sa_family == AF_PACKET) {
            // record interface name & mac address
            found = 0;
            for (int i = 0; i <= ifname_count; i++) {
                if (strcmp(ifa->ifa_name, ifname_list[i]) == 0) {
                    mapIfIndex[ifname_count] = i;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                mapIfIndex[ifname_count] = ifname_count;
            }
            ifname_list[ifname_count] = strdup(ifa->ifa_name);
            mac_list[ifname_count] = macconv_unix2zz((struct sockaddr_ll *)ifa->ifa_addr);
            ifname_count += 1;
        } else {
            continue;
        }
    }
    freeifaddrs(ifaddr);

    *ifs = (adapter_info *)malloc(ifname_count * sizeof(adapter_info));
    int real_count = 0;
    for (int i = 0; i < ifname_count; i++) {
        int real_idx = mapIfIndex[i];
        if (real_idx == -1) {
            continue;
        } else if (real_idx == i) {
            (*ifs)[i].name = ifname_list[i];
            (*ifs)[i].mac = mac_list[i];
            (*ifs)[i].ip_count = 1;
            real_count += 1;
        } else {
            (*ifs)[real_idx].ip_count += 1;
        }
    }
    int ifCountMap[100];
    memset(ifCountMap, 0, sizeof(ifCountMap));
    for (int i = 0; i < ifname_count; i++) {
        int real_idx = mapIfIndex[i];
        if (real_idx == -1) {
            continue;
        } else if (real_idx == i) {
            int ip_index = ifCountMap[real_idx];
            (*ifs)[real_idx].ip = (ip_addr *)malloc((*ifs)[real_idx].ip_count * sizeof(ip_addr));
            (*ifs)[real_idx].ip[ip_index] = ip_list[i];
            ifCountMap[real_idx] += 1;
        } else {
            int ip_index = ifCountMap[real_idx];
            (*ifs)[real_idx].ip[ip_index] = ip_list[i];
            ifCountMap[real_idx] += 1;
        }
    }

    free(ifname_list);
    free(ip_list);
    free(mac_list);
    *count = real_count;

#endif

    return ZZECODE_OK;
}

char *zzmsg_ip2str(ip_addr ip) {
    static char buf[16];
    sprintf(buf, "%d.%d.%d.%d", ip.a, ip.b, ip.c, ip.d);
    return buf;
}

char *zzmsg_udp2str(udp_addr addr) {
    static char buf[32];
    sprintf(buf, "%s:%d", zzmsg_ip2str(addr.ip), addr.port);
    return buf;
}

/* SECTION platform-specific functions */

#ifdef _WIN32

void print_in_addr(struct in_addr addr) {
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) == NULL) {
        printf("inet_ntop failed\n");
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }
    printf("IPv4 Address: %s\n", ip_str);
}

IN_ADDR ipconv_zz2win(u8 a, u8 b, u8 c, u8 d) {
    IN_ADDR addr;
    addr.S_un.S_addr = htonl(a << 24 | b << 16 | c << 8 | d);
    return addr;
}

SOCKADDR_IN addrconv_zz2win(u8 a, u8 b, u8 c, u8 d, u16 port) {
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = ipconv_zz2win(a, b, c, d);
    return addr;
}

udp_addr addrconv_win2zz(SOCKADDR_IN addr) {
    udp_addr zzaddr;
    zzaddr.ip.a = addr.sin_addr.S_un.S_un_b.s_b1;
    zzaddr.ip.b = addr.sin_addr.S_un.S_un_b.s_b2;
    zzaddr.ip.c = addr.sin_addr.S_un.S_un_b.s_b3;
    zzaddr.ip.d = addr.sin_addr.S_un.S_un_b.s_b4;
    zzaddr.port = addr.sin_port;
    return zzaddr;
}

mac_addr addrconv_win2mac(u8 *mac) {
    mac_addr zzmac;
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

udp_addr addrconv_unix2zz(struct sockaddr_in addr) {
    udp_addr zzaddr;
    zzaddr.ip.a = addr.sin_addr.s_addr >> 24;
    zzaddr.ip.b = addr.sin_addr.s_addr >> 16;
    zzaddr.ip.c = addr.sin_addr.s_addr >> 8;
    zzaddr.ip.d = addr.sin_addr.s_addr;
    zzaddr.port = addr.sin_port;
    return zzaddr;
}

mac_addr macconv_unix2zz(struct sockaddr_ll *addr) {
    mac_addr zzmac;
    for (int i = 0; i < addr->sll_halen; ++i) {
        zzmac.addr[i] = addr->sll_addr[i];
    }
    return zzmac;
}

ip_addr ipconv_unix2zz(struct sockaddr_in *addr) {
    u32 ip = addr->sin_addr.s_addr;
    ip_addr zzip;
    zzip.a = ip;
    zzip.b = ip >> 8;
    zzip.c = ip >> 16;
    zzip.d = ip >> 24;
    return zzip;
}

#endif

ip_addr addrconv_str2ip(char *str) {
    ip_addr ip;
    sscanf(str, "%hhu.%hhu.%hhu.%hhu", &ip.a, &ip.b, &ip.c, &ip.d);
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

int set_socket_reusable(const udp_socket *sock) {
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }
#ifdef _WIN32
    int ret = 0;
    setsockopt(*(SOCKET *)(sock->sock_ptr), SOL_SOCKET, SO_REUSEADDR, (char *)&ret, sizeof(ret));
    if (ret) {
        printf("setsockopt(reusable) failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

#ifdef _UNIX
    int ret = 0;
    int *psock = (int *)sock->sock_ptr;
    setsockopt(*(int *)(sock->sock_ptr), SOL_SOCKET, SO_REUSEADDR, (char *)&ret, sizeof(ret));
    if (ret) {
        printf("setsockopt(reusable) failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

    printf("setsockopt(reusable) success\n");
    return ZZECODE_OK;
}

int set_socket_if(const udp_socket *sock, ip_addr ip) {
    int ret;
    if (check_init()) {
        return ZZECODE_NO_INIT;
    }
#ifdef _WIN32
    IN_ADDR addr = ipconv_zz2win(ip.a, ip.b, ip.c, ip.d);
    ret = setsockopt(*(SOCKET *)(sock->sock_ptr), IPPROTO_IP, IP_MULTICAST_IF, (const char *)&addr, sizeof(addr));
    if (ret) {
        printf("setsockopt(if) failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

#ifdef _UNIX
    int *psock = (int *)sock->sock_ptr;
    in_addr_t addr = ipconv_zz2unix(ip.a, ip.b, ip.c, ip.d);
    ret = setsockopt(*(int *)(sock->sock_ptr), IPPROTO_IP, IP_MULTICAST_IF, (const char *)&addr, sizeof(addr));
    if (ret) {
        printf("setsockopt(if) failed, code %d\n", ret);
        return ZZECODE_OS_ERROR;
    }
#endif

    printf("setsockopt(if) success\n");
    return ZZECODE_OK;
}
