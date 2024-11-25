#ifndef ZZUTIL_ZZHEX_H
#define ZZUTIL_ZZHEX_H

void zzhex_base64_encode(char *hex, size_t len, char **base64);

void zzhex_base64_decode(const char *base64, unsigned char **data, size_t *len);

void zzhex_print_data_hex(char *info, unsigned char *data, size_t len);

void zzhex_print_data_base64(char *info, unsigned char *data, size_t len);

#endif // ZZUTIL_ZZHEX_H
