#ifndef ZZUTIL_ZZCRYPT_H
#define ZZUTIL_ZZCRYPT_H

#include <stdio.h>
#include <stdint.h>

struct _zzcrypt_devhandle;
struct _zzcrypt_keyhandle;
typedef struct _zzcrypt_devhandle zzcrypt_devhandle_t, *zzcrypt_devhandle_p;
typedef struct _zzcrypt_keyhandle zzcrypt_keyhandle_t, *zzcrypt_keyhandle_p;

typedef enum _zzcrypt_padding_type {
    zzcrypt_padding_none = 0,
    zzcrypt_padding_pkcs5 = 5,
    zzcrypt_padding_pkcs7 = 7,
} padding_type_t;

typedef struct _block_cipherp_param {
    uint8_t *iv;
    size_t iv_len;
    padding_type_t padding_type;
} block_cipherp_param_t;

int zzcrypt_init(zzcrypt_devhandle_t **hdev, FILE *log);

int zzcrypt_sm2_encrypt(const zzcrypt_devhandle_t *hdev, const uint8_t *pubkey, const uint8_t *data, size_t len, uint8_t **enc_data, size_t *enc_len);

int zzcrypt_sm2_decrypt(const zzcrypt_devhandle_t *hdev, const uint8_t *prikey, const uint8_t *enc_data, size_t enc_len, uint8_t **data, size_t *len);

int zzcrypt_sm2_sign(const zzcrypt_devhandle_t *hdev, const uint8_t *prikey, const uint8_t *data, size_t len, uint8_t **sign, size_t *sign_len);

int zzcrypt_sm2_verify(const zzcrypt_devhandle_t *hdev, const uint8_t *pubkey, const uint8_t *data, size_t len, const uint8_t *sign, size_t sign_len);

int zzcrypt_sm4_import_key(const zzcrypt_devhandle_t *hdev, const uint8_t *key, zzcrypt_keyhandle_t **hkey);

int zzcrypt_sm4_encrypt_init(zzcrypt_keyhandle_t *hkey, block_cipherp_param_t param);

int zzcrypt_sm4_encrypt_push(zzcrypt_keyhandle_t *hkey, const uint8_t *data, size_t len);

int zzcrypt_sm4_encrypt_peek(const zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

int zzcrypt_sm4_encrypt_pop(zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

int zzcrypt_sm4_decrypt_init(zzcrypt_keyhandle_t *hkey, block_cipherp_param_t param);

int zzcrypt_sm4_decrypt_push(zzcrypt_keyhandle_t *hkey, const uint8_t *data, size_t len);

int zzcrypt_sm4_decrypt_peek(const zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

int zzcrypt_sm4_decrypt_pop(zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

#endif // ZZUTIL_ZZCRYPT_H
