#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zzmessage.h>

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

    // send udp message
    while (1) {
        char str[] = "Hello, World!";
        ret = zzmsg_send_udp(socket, addr, str, strlen(str));
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
