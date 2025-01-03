#ifndef ZZUTIL_ZZCAPTURE_H
#define ZZUTIL_ZZCAPTURE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct zzcapture_param zzcapture_param_t;
typedef struct zzcapture_param *zzcapture_param_p;
typedef struct zzcapture_handle_ zzcapture_handle_t;
typedef struct zzcapture_handle_ *zzcapture_handle_p;

struct zzcapture_param {
    size_t bit_rate;
    size_t height;
    size_t width;
};

int zzcapture_init(zzcapture_handle_t **hcap, const zzcapture_param_t *param, FILE *log);

int zzcapture_get_ts_packet(const zzcapture_handle_t *hcap, uint8_t **data, size_t *len);

#endif // ZZUTIL_ZZCAPTURE_H
