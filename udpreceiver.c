#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zzmessage.h>

#include "testutil.h"

int main(int agrc, char *agrv[]) {
    int ret;

    // bind sockets
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

    // bind recive socket
    ret = zzmsg_bind_socket(socket, port);
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
    udp_address from;
    u32 receive_len;
    // NOTE
    while (1) {
        ret = zzmsg_recv_udp(socket, &from, buf, 1024, &receive_len);
        if (ret) {
            printf("recv failed\n");
            continue;
        } else {
            printf("recv: %s\n", buf);
            printf("from: %s\n", udp2str(from));
            printf("total: %d bytes\n", receive_len);
        }

        sleep(1000);
    }

    pasue_on_exit();
    return 0;
}
