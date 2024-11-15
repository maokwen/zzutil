#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN_MINGW
#include <winsock2.h>
#endif

#ifdef UNIX
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

void pasue_on_exit() {
#ifdef _WIN32
    system("pause");
#endif
}


int main(int agrc, char *agrv[]) {
    printf("hello world\n");
    pasue_on_exit();
    return 0;
}