#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zzmessage.h>

#ifdef _WIN32
#include <windows.h>
#endif

void pasue_on_exit() {
#ifdef _WIN32
    system("pause");
#endif
}

void sleep(int ms) {
#ifdef _WIN32
    Sleep(ms);
#endif
}

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
    while (1) {
        u8 buf[1024];
        zzmsg_recv_udp(socket, &addr, buf, 1024);
        printf("recv: %s\n", buf);
        sleep(1000);
    }

    pasue_on_exit();
    return 0;
}
