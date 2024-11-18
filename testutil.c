#ifdef _WIN32
#include <windows.h>
#elif _UNIX
#include <unistd.h>
#endif

void pasue_on_exit() {
#ifdef _WIN32
    system("pause");
#endif
}

void dosleep(int ms) {
#ifdef _WIN32
    Sleep(ms);
#endif
#ifdef _UNIX
    usleep(ms * 1000);
#endif
}
