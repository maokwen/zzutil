#include <stdio.h>

#include "helper.h"
#include "zzutil/basetype.h"

char *ip2str(struct _ip_address ip) {
    static char buf[16];
    sprintf(buf, "%d.%d.%d.%d", ip.a, ip.b, ip.c, ip.d);
    return buf;
}

char *udp2str(struct _udp_address addr) {
    static char buf[32];
    sprintf(buf, "%s:%d", ip2str(addr.ip), addr.port);
    return buf;
}
