#ifndef ZZUTIL_ZZHEX_H
#define ZZUTIL_ZZHEX_H

int zzhex_base64_encode(char *hex, size_t len, char **base64);

int zzhex_base64_decode(const char *base64, unsigned char **data, size_t *len);

int zzhex_print_data_hex(char *info, unsigned char *data, size_t len);

int zzhex_print_data_base64(char *info, unsigned char *data, size_t len);

int zzhex_hex_to_bin(const char *hex, unsigned char **data, size_t *len);

int zzhex_bin_to_hex(const unsigned char *data, size_t len, char **hex);

#endif // ZZUTIL_ZZHEX_H
