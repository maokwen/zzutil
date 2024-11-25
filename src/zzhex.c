#include <zzutil/basetype.h>
#include <zzutil/zzhex.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void zzhex_base64_encode(char *hex, size_t len, char **base64) {
    u8 *hex_data = (u8 *)hex;
    u8 *base64_data = (u8 *)malloc(len / 3 * 4 + 4);
    int i = 0;

    for (i = 0; i < len; i += 3) {
        base64_data[i / 3 * 4 + 0] = base64_table[(hex_data[i] >> 2) & 0x3f];
        base64_data[i / 3 * 4 + 1] = base64_table[((hex_data[i] << 4) | (hex_data[i + 1] >> 4)) & 0x3f];
        base64_data[i / 3 * 4 + 2] = base64_table[((hex_data[i + 1] << 2) | (hex_data[i + 2] >> 6)) & 0x3f];
        base64_data[i / 3 * 4 + 3] = base64_table[hex_data[i + 2] & 0x3f];
    }

    if (i == len + 1) {
        base64_data[i / 3 * 4 + 0] = base64_table[(hex_data[i] >> 2) & 0x3f];
        base64_data[i / 3 * 4 + 1] = base64_table[(hex_data[i] << 4) & 0x3f];
        base64_data[i / 3 * 4 + 2] = '=';
        base64_data[i / 3 * 4 + 3] = '=';
    }

    if (i == len + 2) {
        base64_data[i / 3 * 4 + 0] = base64_table[(hex_data[i] >> 2) & 0x3f];
        base64_data[i / 3 * 4 + 1] = base64_table[((hex_data[i] << 4) | (hex_data[i + 1] >> 4)) & 0x3f];
        base64_data[i / 3 * 4 + 2] = base64_table[(hex_data[i + 1] << 2) & 0x3f];
        base64_data[i / 3 * 4 + 3] = '=';
    }

    base64_data[i / 3 * 4 + 4] = 0;

    *base64 = (char *)base64_data;

    return;
}

void zzhex_base64_decode(const char *base64, unsigned char **data, size_t *len) {
    size_t base64_len = strlen(base64);
    if (base64_len % 4 != 0) {
        *data = NULL;
        *len = 0;
        return;
    }

    size_t padding = 0;
    if (base64_len >= 2 && base64[base64_len - 1] == '=' && base64[base64_len - 2] == '=') {
        padding = 2;
    } else if (base64_len >= 1 && base64[base64_len - 1] == '=') {
        padding = 1;
    }

    *len = (base64_len / 4) * 3 - padding;
    *data = (unsigned char *)malloc(*len);

    unsigned char *p = *data;
    for (size_t i = 0; i < base64_len; i += 4) {
        u32 n = (u32)((strchr(base64_table, base64[i]) - base64_table) << 18 |
                         (strchr(base64_table, base64[i + 1]) - base64_table) << 12 |
                         (strchr(base64_table, base64[i + 2]) - base64_table) << 6 |
                         (strchr(base64_table, base64[i + 3]) - base64_table));

        *p++ = (n >> 16) & 0xFF;
        if (base64[i + 2] != '=')
            *p++ = (n >> 8) & 0xFF;
        if (base64[i + 3] != '=')
            *p++ = n & 0xFF;
    }
}

void zzhex_print_data_hex(char *info, unsigned char *data, size_t len) {
    if (info)
        printf("%s\n", info);

    for (unsigned i = 0; i < len; i++) {
        if (i && i % 16 == 0)
            printf("\n");
        printf("%02x", data[i]);
    }
    printf("\n");
}

void zzhex_print_data_base64(char *info, unsigned char *data, size_t len) {
    char *res;
    zzhex_base64_encode((char *)data, len, &res);
    printf("%s: %s\n", info, res);
}
