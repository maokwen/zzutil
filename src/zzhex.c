#include <zzutil/basetype.h>
#include <zzutil/zzhex.h>
#include <zzutil/errmsg.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char hex_table[] = "0123456789abcdef";

/************************************************************
 * Declears
 ************************************************************/

static void to_lower_case(char *str);

/************************************************************
 * Public functions
 ************************************************************/

int zzhex_base64_encode(char *hex, size_t len, char **base64) {
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

    return ZZECODE_OK;
}

int zzhex_base64_decode(const char *base64, unsigned char **data, size_t *len) {
    size_t base64_len = strlen(base64);
    if (base64_len % 4 != 0) {
        *data = NULL;
        *len = 0;
        return ZZECODE_PARAM_ERR;
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

    return ZZECODE_OK;
}

int zzhex_print_data_hex(char *info, unsigned char *data, size_t len) {
    if (info) {
        printf("%s\n", info);
    }
    for (unsigned i = 0; i < len; ++i) {
        if ((i + 1) % 16 == 0) {
            printf("%02x\n", data[i]);
        } else {
            printf("%02x ", data[i]);
        }
    }
    printf("\n");

    return ZZECODE_OK;
}

int zzhex_print_data_base64(char *info, unsigned char *data, size_t len) {
    char *res;
    zzhex_base64_encode((char *)data, len, &res);
    printf("%s: %s\n", info, res);

    return ZZECODE_OK;
}

int zzhex_hex_to_bin(const char *hex, unsigned char **data, size_t *len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        *data = NULL;
        *len = 0;
        return ZZECODE_PARAM_ERR;
    }

    char *s = (char *)malloc(hex_len + 1);
    strcpy(s, hex);
    to_lower_case(s);

    *len = hex_len / 2;
    *data = (u8 *)malloc(*len);

    for (size_t i = 0; i < hex_len; i += 2) {
        (*data)[i / 2] = (u8)(
            (strchr(hex_table, s[i]) - hex_table) << 4 |
            (strchr(hex_table, s[i + 1]) - hex_table)
        );
    }

    return ZZECODE_OK;
}

int zzhex_bin_to_hex(const unsigned char *data, size_t len, char **hex) {
    *hex = (char *)malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        (*hex)[i * 2] = hex_table[data[i] >> 4];
        (*hex)[i * 2 + 1] = hex_table[data[i] & 0x0f];
    }
    (*hex)[len * 2] = 0;

    return ZZECODE_OK;
}

/************************************************************
 * Internal functions
 ************************************************************/

void to_lower_case(char *str) {
    while (*str) {
        if (*str >= 'A' && *str <= 'Z') {
            *str += 32;
        }
        str++;
    }
}
