#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zzutil/zzmessage.h>

#include "testutil.h"

int main(int agrc, char *agrv[]) {
    int ret;

    ip_address ip = {239, 255, 43, 21};
    u16 port = 30040;
    udp_address addr = {ip, port};

    udp_socket socket;

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
    ip_address local_ip = {0, 0, 0, 0};
    for (u32 i = 0; i < count; i++) {
        printf("name: %s\n", ifs[i].name);
        if (ifs[i].mac.is_valid) {
            printf("mac: %2lX:%2lX:%2lX:%2lX:%2lX:%2lX\n", ifs[i].mac.addr[0], ifs[i].mac.addr[1], ifs[i].mac.addr[2], ifs[i].mac.addr[3], ifs[i].mac.addr[4], ifs[i].mac.addr[5]);
        }
        for (int j = 0; j < ifs[i].ip_count; j++) {
            printf("ip: %s\n", ip2str(ifs[i].ip[j]));
            if (ifs[i].ip[j].a == 192 && ifs[i].ip[j].b == 168 && ifs[i].ip[j].c == 28) {
                local_ip = ifs[i].ip[j];
                break;
            }
        }
    }
    printf("local ip: %s\n", ip2str(local_ip));

    // send udp messageP
    while (1) {
        char str[] = "Hello, World!";
        ret = zzmsg_send_udp(socket, addr, str, strlen(str), &local_ip);
        if (ret) {
            pasue_on_exit();
            return ret;
        }
        printf("send: %s\n", str);

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
