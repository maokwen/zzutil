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
#ifdef _UNIX
    sleep(ms);
#endif
}
