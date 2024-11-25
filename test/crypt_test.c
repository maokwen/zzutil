#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <zzutil/errmsg.h>
#include <zzutil/zzcrypt.h>
#include <zzutil/zzhex.h>

void test_sm4_ecb(zzcrypt_devhandle_p hdev) {
    int ret;
    uint8_t key[16] = {
        0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec
    };
    uint8_t data[16] = {
        0x5f,0xe9,0x7c,0xcd,0x58,0xfe,0xd7,0xab,0x41,0xf7,0x1e,0xfb,0xfd,0xe7,0xe1,0x46
    };
    uint8_t enc_data_expect[] = {
        0x56,0xda,0x23,0xe2,0x5f,0xa7,0xcd,0x82,0x5d,0x51,0xc2,0x20,0xf5,0x98,0x09,0x0b
    };

    zzcrypt_keyhandle_p hkey;
    ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    zzcrypt_cipherp_param_t param;
    param.algorithm = zzcrypt_algorithm_sm4ecb;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_none;
    ret = zzcrypt_sm4_encrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    zzhex_print_data_hex("     uncrypted data", data, 16);

    assert(ret == ZZECODE_OK);
    ret = zzcrypt_sm4_encrypt_push(hkey, data, 16);

    uint8_t *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    uint8_t *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    assert(memcmp(enc_data_expect, enc_data, 16) == 0);
    assert(memcmp(data, dec_data, 16) == 0);
    printf("=====test_sm4_ecb passed\n");
}

void test_sm4_ecb_padding(zzcrypt_devhandle_p hdev) {
    int ret;
    uint8_t key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    uint8_t data[] = {0x11,0x22,0x33};   //1122330d0d0d0d0d0d0d0d0d0d0d0d0d
    uint8_t enc_data_expect[] = {0x2C,0xFE,0xC5,0x55,0xF0,0xE7,0x0B,0x7A,0xC1,0xD2,0x0A,0xC3,0xD2,0xC5,0x85,0x11};

    zzcrypt_keyhandle_p hkey;
    ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    zzcrypt_cipherp_param_t param;
    param.algorithm = zzcrypt_algorithm_sm4ecb;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_pkcs5;
    ret = zzcrypt_sm4_encrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    zzhex_print_data_hex("     uncrypted data", data, 16);

    assert(ret == ZZECODE_OK);
    ret = zzcrypt_sm4_encrypt_push(hkey, data, 3);

    uint8_t *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    uint8_t *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    assert(memcmp(enc_data_expect, enc_data, 16) == 0);
    assert(memcmp(data, dec_data, dec_len) == 0);
    printf("=====test_sm4_ecb_padding passed\n");
}

void test_sm4_ecb_padding_zero(zzcrypt_devhandle_p hdev) {
    uint8_t key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    uint8_t data[] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};//11223344556677889907070707070707
    uint8_t enc_data_expect[] = {0xA3,0x5C,0xC2,0xB1,0x54,0xD6,0xE8,0xAB,0x9D,0x7C,0xA6,0xB9,0xC3,0x76,0x7D,0x0C};

    zzcrypt_keyhandle_p hkey;
    int ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    zzcrypt_cipherp_param_t param;
    param.algorithm = zzcrypt_algorithm_sm4ecb;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_zero;
    ret = zzcrypt_sm4_encrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    zzhex_print_data_hex("     uncrypted data", data, 16);
    
    ret = zzcrypt_sm4_encrypt_push(hkey, data, 9);
    assert(ret == ZZECODE_OK);

    uint8_t *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    uint8_t *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    assert(memcmp(enc_data_expect, enc_data, 16) == 0);
    assert(memcmp(data, dec_data, dec_len) == 0);
    printf("=====test_sm4_ecb_padding2 passed\n");
}

void test_sm4_ecb_padding_pkcs5(zzcrypt_devhandle_p hdev) {
    int ret = 0;
    uint8_t key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    uint8_t data[] = {0x5f,0xe9,0x7c,0xcd,0x58,0xfe,0xd7,0xab,0x41,0xf7,0x1e,0xfb,0xfd,0xe7,0xe1,0x46};
    uint8_t result[] = {0x56,0xda,0x23,0xe2,0x5f,0xa7,0xcd,0x82,0x5d,0x51,0xc2,0x20,0xf5,0x98,0x09,0x0b,
                0x4C,0xE1,0x33,0x10,0xBE,0xC0,0x7F,0x88,0xF1,0xD0,0x1B,0xA7,0x86,0x69,0xAF,0x28};

    zzcrypt_keyhandle_p hkey;
    ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    zzcrypt_cipherp_param_t param;
    param.algorithm = zzcrypt_algorithm_sm4ecb;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_pkcs5;
    ret = zzcrypt_sm4_encrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    zzhex_print_data_hex("     uncrypted data", data, 16);

    assert(ret == ZZECODE_OK);
    ret = zzcrypt_sm4_encrypt_push(hkey, data, 16);

    uint8_t *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    uint8_t *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    assert(memcmp(result, enc_data, enc_len) == 0);
    assert(memcmp(data, dec_data, 16) == 0);
    printf("=====test_sm4_ecb_pkcs5 passed\n");

}

void test_sm4_cbc(zzcrypt_devhandle_p hdev) {
    int ret = 0;
    uint8_t  key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    uint8_t  data[] = {0x5f,0xe9,0x7c,0xcd,0x58,0xfe,0xd7,0xab,0x41,0xf7,0x1e,0xfb,0xfd,0xe7,0xe1,0x46};
    uint8_t  result[] = {0x56,0xda,0x23,0xe2,0x5f,0xa7,0xcd,0x82,0x5d,0x51,0xc2,0x20,0xf5,0x98,0x09,0x0b,
                0x4C,0xE1,0x33,0x10,0xBE,0xC0,0x7F,0x88,0xF1,0xD0,0x1B,0xA7,0x86,0x69,0xAF,0x28};

    zzcrypt_keyhandle_p hkey;
    ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    zzcrypt_cipherp_param_t param;
    param.algorithm = zzcrypt_algorithm_sm4cbc;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_none;
    ret = zzcrypt_sm4_encrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    zzhex_print_data_hex("     uncrypted data", data, 16);

    assert(ret == ZZECODE_OK);
    ret = zzcrypt_sm4_encrypt_push(hkey, data, 16);

    uint8_t *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    uint8_t *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    assert(memcmp(result, enc_data, enc_len) == 0);
    assert(memcmp(data, dec_data, 16) == 0);
    printf("=====test_sm4_cbc passed\n");
}

int main() {
    int ret;

    zzcrypt_devhandle_p hdev;
    ret = zzcrypt_init(&hdev, stderr);
    assert(ret == ZZECODE_OK);

    test_sm4_ecb(hdev);
    test_sm4_ecb_padding(hdev);
    test_sm4_ecb_padding_zero(hdev);
    test_sm4_ecb_padding_pkcs5(hdev);
    test_sm4_cbc(hdev);

    return 0;
}
