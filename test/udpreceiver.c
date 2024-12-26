#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <zzutil/zzmessage.h>

#include "testutil.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef zzmsg_udp_socket_t udp_socket;
typedef zzmsg_ip_address_t ip_addr;
typedef zzmsg_mac_address_t mac_addr;
typedef zzmsg_udp_address_t udp_addr;
typedef zzmsg_adapter_info_t adapter_info;

bool starts_with(const char *str, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    size_t str_len = strlen(str);
    if (str_len < prefix_len) {
        return false;
    }
    return strncmp(str, prefix, prefix_len) == 0;
}

int main(int agrc, char *agrv[]) {
    int ret;

    zzmsg_ip_address_t ip = {239, 255, 43, 21};
    u16 port = 30040;
    zzmsg_udp_address_t addr = {ip, port};

    zzmsg_udp_socket_t *socket = NULL;

    ret = zzmsg_init();
    if (ret) {
        pasue_on_exit();
        return ret;
    }

    ret = zzmsg_create_socket(&socket);
    if (ret) {
        pasue_on_exit();
        return ret;
    }

    // get all interfaces
    adapter_info *ifs;
    u32 count;
    ret = zzmsg_get_all_interfaces(&ifs, &count);
    if (ret) {
        pasue_on_exit();
        return ret;
    }

    // get local ip
    ip_addr local_ip = {0, 0, 0, 0};
    for (u32 i = 0; i < count; i++) {
        printf("name: %s\n", ifs[i].name);
        if (ifs[i].mac.is_valid) {
            printf("mac: %02X:%02X:%02X:%02X:%02X:%02X\n", ifs[i].mac.addr[0], ifs[i].mac.addr[1], ifs[i].mac.addr[2], ifs[i].mac.addr[3], ifs[i].mac.addr[4], ifs[i].mac.addr[5]);
        }
        for (int j = 0; j < ifs[i].ip_count; j++) {
            printf("ip: %s\n", zzmsg_ip2str(ifs[i].ip[j]));
            if (ifs[i].ip[j].a == 192 && ifs[i].ip[j].b == 168 && ifs[i].ip[j].c == 28) {
                local_ip = ifs[i].ip[j];
                break;
            }
        }
        printf("\n");
    }
    printf("local ip: %s\n", zzmsg_ip2str(local_ip));

    // bind recive socket
    ret = zzmsg_bind_socket(socket, port, &local_ip);
    if (ret) {
        pasue_on_exit();
        return ret;
    }

    // bind multicast group
    ret = zzmsg_join_multicast_group(socket, ip);
    if (ret) {
        pasue_on_exit();
        return ret;
    }

    // receive message
    u8 buf[1024];
    udp_addr from;
    u32 receive_len;
    while (1) {
        printf("waiting for message...\n");
        ret = zzmsg_recv_udp(socket, &from, buf, 1024, &receive_len);
        if (ret) {
            printf("recv failed\n");
            continue;
        } else {
            printf("recv: %s\n", buf);
            printf("from: %s\n", zzmsg_udp2str(from));
            printf("total: %d bytes\n", receive_len);
        }

        dosleep(1000);
    }

    ret = zzmsg_close_socket(socket);
    if (ret) {
        pasue_on_exit();
        return ret;
    }

    pasue_on_exit();
    return 0;
}
