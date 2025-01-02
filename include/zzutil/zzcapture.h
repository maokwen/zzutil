#ifndef ZZUTIL_ZZCAPTURE_H
#define ZZUTIL_ZZCAPTURE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct zzcapture_handle_ zzcapture_handle_t;

int zzcapture_init(zzcapture_handle_t **hcap, FILE *log);

int zzcapture_get_ts_packet(const zzcapture_handle_t *hcap, uint8_t **data, size_t *len);

#endif // ZZUTIL_ZZCAPTURE_H
