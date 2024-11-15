#include <stdint.h>

#ifdef _WIN32
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

typedef struct _udp_socket {
    void *sock_ptr;
} udp_socket;
