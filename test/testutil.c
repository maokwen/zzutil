#ifdef _WIN32
#include <windows.h>
#elif _UNIX
#include <unistd.h>
#include <sys/time.h>
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

void dosleep_timeofday(int ms) {
#ifdef _WIN32
    Sleep(ms);
#endif
#ifdef _UNIX
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double begin = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
    while (1) {
        gettimeofday(&tv, NULL);
        double end = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
        if (end - begin >= ms) {
            break;
        }
    }
#endif
}
