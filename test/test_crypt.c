#include <zzutil/errmsg.h>
#include <zzutil/zzcrypt.h>
#include <zzutil/zzhex.h>

#include "testutil.h"

void test_sm4_ecb(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_ecb\n");
    int ret;
    u8 key[16] = {
        0x77, 0x7f, 0x23, 0xc6, 0xfe, 0x7b, 0x48, 0x73, 0xdd, 0x59, 0x5c, 0xff, 0xf6, 0x5f, 0x58, 0xec};
    u8 data[16] = {
        0x5f, 0xe9, 0x7c, 0xcd, 0x58, 0xfe, 0xd7, 0xab, 0x41, 0xf7, 0x1e, 0xfb, 0xfd, 0xe7, 0xe1, 0x46};
    u8 enc_data_expect[] = {
        0x56, 0xda, 0x23, 0xe2, 0x5f, 0xa7, 0xcd, 0x82, 0x5d, 0x51, 0xc2, 0x20, 0xf5, 0x98, 0x09, 0x0b};

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

    u8 *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
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

    zzcrypt_sm4_release(hkey);
    printf("=====test_sm4_ecb passed\n");
}

void test_sm4_ecb_padding(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_ecb_padding\n");
    int ret;
    u8 key[] = {0x77, 0x7f, 0x23, 0xc6, 0xfe, 0x7b, 0x48, 0x73, 0xdd, 0x59, 0x5c, 0xff, 0xf6, 0x5f, 0x58, 0xec};
    u8 data[] = {0x11, 0x22, 0x33}; // 1122330d0d0d0d0d0d0d0d0d0d0d0d0d
    u8 enc_data_expect[] = {0x2C, 0xFE, 0xC5, 0x55, 0xF0, 0xE7, 0x0B, 0x7A, 0xC1, 0xD2, 0x0A, 0xC3, 0xD2, 0xC5, 0x85, 0x11};

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

    u8 *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
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

    zzcrypt_sm4_release(hkey);
    printf("=====test_sm4_ecb_padding passed\n");
}

void test_sm4_ecb_padding_zero(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_ecb_padding_zero\n");
    u8 key[] = {0x77, 0x7f, 0x23, 0xc6, 0xfe, 0x7b, 0x48, 0x73, 0xdd, 0x59, 0x5c, 0xff, 0xf6, 0x5f, 0x58, 0xec};
    u8 data[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}; // 11223344556677
    u8 enc_data_expect[] = {0x33, 0x55, 0xcd, 0x38, 0x97, 0x7a, 0xdb, 0xc8, 0x8a, 0x46, 0xee, 0xf4, 0xfd, 0x6d, 0x71, 0xb4};

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

    zzhex_print_data_hex("     uncrypted data", data, 7);

    ret = zzcrypt_sm4_encrypt_push(hkey, data, 7);
    assert(ret == ZZECODE_OK);

    u8 *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    assert(memcmp(enc_data_expect, enc_data, 16) == 0);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    assert(dec_len == 7);
    assert(memcmp(data, dec_data, 7) == 0);

    zzcrypt_sm4_release(hkey);
    printf("=====test_sm4_ecb_padding2 passed\n");
}

void test_sm4_ecb_padding_pkcs5(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_ecb_padding_pkcs5\n");
    int ret = 0;
    u8 key[] = {0x77, 0x7f, 0x23, 0xc6, 0xfe, 0x7b, 0x48, 0x73, 0xdd, 0x59, 0x5c, 0xff, 0xf6, 0x5f, 0x58, 0xec};
    u8 data[] = {0x5f, 0xe9, 0x7c, 0xcd, 0x58, 0xfe, 0xd7, 0xab, 0x41, 0xf7, 0x1e, 0xfb, 0xfd, 0xe7, 0xe1, 0x46};
    u8 result[] = {0x56, 0xda, 0x23, 0xe2, 0x5f, 0xa7, 0xcd, 0x82, 0x5d, 0x51, 0xc2, 0x20, 0xf5, 0x98, 0x09, 0x0b,
                   0x4C, 0xE1, 0x33, 0x10, 0xBE, 0xC0, 0x7F, 0x88, 0xF1, 0xD0, 0x1B, 0xA7, 0x86, 0x69, 0xAF, 0x28};

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

    u8 *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    zzcrypt_sm4_release(hkey);

    assert(memcmp(result, enc_data, enc_len) == 0);
    assert(memcmp(data, dec_data, 16) == 0);
    printf("=====test_sm4_ecb_pkcs5 passed\n");
}

void test_sm4_cbc(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_cbc\n");
    int ret = 0;
    u8 key[] = {0x77, 0x7f, 0x23, 0xc6, 0xfe, 0x7b, 0x48, 0x73, 0xdd, 0x59, 0x5c, 0xff, 0xf6, 0x5f, 0x58, 0xec};
    u8 data[] = {0x5f, 0xe9, 0x7c, 0xcd, 0x58, 0xfe, 0xd7, 0xab, 0x41, 0xf7, 0x1e, 0xfb, 0xfd, 0xe7, 0xe1, 0x46};
    u8 result[] = {0x56, 0xda, 0x23, 0xe2, 0x5f, 0xa7, 0xcd, 0x82, 0x5d, 0x51, 0xc2, 0x20, 0xf5, 0x98, 0x09, 0x0b,
                   0x4C, 0xE1, 0x33, 0x10, 0xBE, 0xC0, 0x7F, 0x88, 0xF1, 0xD0, 0x1B, 0xA7, 0x86, 0x69, 0xAF, 0x28};

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

    u8 *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
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

    zzcrypt_sm4_release(hkey);
    printf("=====test_sm4_cbc passed\n");
}

void test_sm4_ecb_17(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_ecb_17\n");
    int ret;
    u8 key[16] = {
        0x77, 0x7f, 0x23, 0xc6, 0xfe, 0x7b, 0x48, 0x73, 0xdd, 0x59, 0x5c, 0xff, 0xf6, 0x5f, 0x58, 0xec};
    u8 data[34] = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
        0x99,
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
        0x99,
    };

    zzcrypt_keyhandle_p hkey;
    ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    zzcrypt_cipherp_param_t param;
    param.algorithm = zzcrypt_algorithm_sm4ecb;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_pkcs7;
    ret = zzcrypt_sm4_encrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    zzhex_print_data_hex("     uncrypted data", data, 34);

    assert(ret == ZZECODE_OK);
    ret = zzcrypt_sm4_encrypt_push(hkey, data, 34);

    u8 *enc_data;
    size_t enc_len;

    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, enc_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    assert(dec_len == 34);
    assert(memcmp(data, dec_data, 34) == 0);

    zzcrypt_sm4_release(hkey);
    printf("=====test_sm4_ecb passed\n");
}

void test_sm4_ecb_long(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_ecb_long\n");
    int ret = 0;
    u8 key[] = {0x77, 0x7f, 0x23, 0xc6, 0xfe, 0x7b, 0x48, 0x73, 0xdd, 0x59, 0x5c, 0xff, 0xf6, 0x5f, 0x58, 0xec};
    u8 data[1024];
    for (size_t i = 0; i < 1024; i++) {
        data[i] = i % 256;
    }

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

    zzhex_print_data_hex("     uncrypted data", data, 1024);

    u8 *enc_data;
    size_t enc_len;
    size_t offset = 0;
    size_t remain = 1024;
    while (remain > 0) {
        size_t len = remain > 16 ? 16 : remain;
        ret = zzcrypt_sm4_encrypt_push(hkey, data + offset, len);
        assert(ret == ZZECODE_OK);
        offset += len;
        remain -= len;
    }

    enc_len = 0;
    ret = zzcrypt_sm4_encrypt_peek(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek encrypted data", enc_data, enc_len);
    free(enc_data);
    enc_data = NULL;

    enc_len = 0;
    ret = zzcrypt_sm4_encrypt_pop(hkey, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  encrypted data", enc_data, enc_len);

    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
    size_t dec_len;
    offset = 0;

    remain = 1024;
    while (remain > 0) {
        size_t len = remain > 16 ? 16 : remain;
        ret = zzcrypt_sm4_decrypt_push(hkey, enc_data + offset, len);
        assert(ret == ZZECODE_OK);
        offset += len;
        remain -= len;
    }

    enc_len = 0;
    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);
    free(dec_data);
    enc_data = NULL;

    enc_len = 0;
    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);
    assert(memcmp(data, dec_data, 1024) == 0);
    free(dec_data);
    enc_data = NULL;

    zzcrypt_sm4_release(hkey);
    printf("=====test_sm4_ecb_long passed\n");
}

void test_sm2(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm2\n");
    int ret = 0;

    u8 *pubkey, *prikey;
    u64 pubkey_len, prikey_len;

    // ret = zzhex_hex_to_bin("5BEEA547827C848B91316C5B9CC82B3B4BD18F1A9245C2B2665AA0E728CBF17B", &prikey, &prikey_len);
    // assert(ret == ZZECODE_OK);
    // zzhex_print_data_hex("pri key", prikey, prikey_len);
    // ret = zzhex_hex_to_bin("84b95a646129866de8d9a150b2974a203815eba87c6322a6d789f5f6fb3e147b1e1c0c547a0dd1789cd510f631f9264af070839a6927d5fd680f76f6e3ba2dd3", &pubkey, &pubkey_len);
    // assert(ret == ZZECODE_OK);
    // zzhex_print_data_hex("pub key", pubkey, pubkey_len);
    // assert(prikey_len == 32);
    // assert(pubkey_len == 64);

    // 19795df701f39d1fb220c45fa7fa4ebfadd1702537b946cd3d4804b37fbc3ea5
    // 2b2ceed6cc042b5bbb568ded3b3673f288e19cc49ae3c350d2b80903d86d912c
    u8 keypair[] = {
        // x
        0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf,
        0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
        // y
        0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2,
        0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
        // d
        0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a,
        0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc};

    pubkey = keypair;
    pubkey_len = 64;
    prikey = keypair + 64;
    prikey_len = 32;

    // u8 data[3] = {0x11,0x22,0x33};
    u8 data[3] = {0x11, 0x22, 0x33};
    u8 *enc_data;
    size_t enc_len;
    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "Thinta_Application", "111111", &happ);
    zzcrypt_sm2_import_key(hdev, happ, prikey, pubkey);
    zzcrypt_sm2_encrypt(hdev, pubkey, data, 3, &enc_data, &enc_len);
    zzhex_print_data_hex("enc_data", enc_data, enc_len);
    printf("enc_len=%d\n", enc_len);

    // u8 mytestdata[167] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //                     0x36, 0x8f, 0xcd, 0xa1, 0x27, 0x61, 0xa0, 0xa2, 0xc2, 0x9d, 0x05, 0xb1, 0x5f, 0xb1, 0xf4, 0xf2,
    //                     0xae, 0x38, 0x14, 0xae, 0x0d, 0x2b, 0xed, 0xc4, 0x50, 0xba, 0x5b, 0x9e, 0xbe, 0x0e, 0x65, 0xa4,
    //                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //                     0xf8, 0x34, 0x3b, 0x90, 0x93, 0xe9, 0xbe, 0xe7, 0x18, 0xdc, 0x6c, 0x01, 0xe3, 0xc8, 0x92, 0x3f,
    //                     0xf8, 0x59, 0x67, 0xf1, 0x84, 0x4c, 0xa7, 0x7f, 0xa0, 0xea, 0xa8, 0x5f, 0x53, 0x4e, 0xea, 0xe1,
    //                     0xf8, 0x09, 0xd9, 0xf2, 0xa6, 0x1a, 0xae, 0x40, 0x6d, 0xa8, 0x3c, 0x3c, 0xd2, 0xf0, 0x32, 0x9b,
    //                     0x28, 0x57, 0xb8, 0x62, 0xd2, 0x25, 0x1a, 0xc6, 0x85, 0x09, 0x5a, 0x62, 0xa6, 0x64, 0xc8, 0x66,
    //                     0x03, 0x00, 0x00, 0x00, 0x45, 0x5c, 0x2e};
    // zzhex_print_data_hex("my_data", &mytestdata, enc_len);

    u8 mytestData[167] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x2a, 0xf9, 0x8d, 0x72, 0x53, 0xc4, 0x19, 0xed, 0x0c, 0xef, 0x77, 0x4e, 0xe3, 0x6a, 0xf6, 0x7e,
                          0xe1, 0x33, 0xb9, 0x00, 0x10, 0x32, 0x28, 0x58, 0x70, 0x84, 0x37, 0x22, 0x22, 0x90, 0x0d, 0x90,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x5f, 0x87, 0xac, 0x80, 0x81, 0xef, 0x91, 0x90, 0xd1, 0x7f, 0xeb, 0xe4, 0x35, 0x28, 0x0e, 0x00,
                          0xb1, 0xa6, 0x7f, 0x8f, 0x70, 0xa6, 0xea, 0x4f, 0x19, 0x39, 0x98, 0xc8, 0x68, 0xdc, 0x0a, 0x62,
                          0x08, 0x74, 0x62, 0x73, 0xef, 0x38, 0xa9, 0xac, 0xfb, 0x75, 0x5e, 0xb5, 0x22, 0x26, 0xe1, 0x5a,
                          0x7b, 0x8d, 0x06, 0x33, 0x26, 0x36, 0x24, 0x27, 0x82, 0xbb, 0x1d, 0x79, 0xf4, 0xce, 0x1a, 0x92,
                          0x03, 0x00, 0x00, 0x00, 0x65, 0x6c, 0x97};

    u8 *dec_data;
    size_t dec_len;
    zzcrypt_sm2_decrypt(hdev, prikey, mytestData, enc_len, &dec_data, &dec_len);
    zzhex_print_data_hex("dec_data", dec_data, dec_len);

    assert(memcmp(data, dec_data, 3) == 0);
    printf("=====test_sm2 passed\n");
}

void test_sm2_from_hex(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm2_from_hex\n");
    int ret = 0;

    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "Thinta_Application", "111111", &happ);

    u8 *pubkey, *prikey;
    size_t pubkey_len, prikey_len;

    ret = zzhex_hex_to_bin("5BEEA547827C848B91316C5B9CC82B3B4BD18F1A9245C2B2665AA0E728CBF17B", &prikey, &prikey_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pri key", prikey, prikey_len);
    ret = zzhex_hex_to_bin("84b95a646129866de8d9a150b2974a203815eba87c6322a6d789f5f6fb3e147b1e1c0c547a0dd1789cd510f631f9264af070839a6927d5fd680f76f6e3ba2dd3", &pubkey, &pubkey_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pub key", pubkey, pubkey_len);
    assert(prikey_len == 32);
    assert(pubkey_len == 64);

    zzcrypt_sm2_import_key(hdev, happ, prikey, pubkey);

    u8 data[3] = {0x11, 0x22, 0x33};
    u8 *enc_data;
    size_t enc_len;
    zzcrypt_sm2_encrypt(hdev, pubkey, data, 3, &enc_data, &enc_len);
    zzhex_print_data_hex("enc_data", enc_data, enc_len);

    u8 *dec_data;
    size_t dec_len;
    zzcrypt_sm2_decrypt(hdev, prikey, enc_data, enc_len, &dec_data, &dec_len);
    zzhex_print_data_hex("dec_data", dec_data, dec_len);

    assert(memcmp(data, dec_data, 3) == 0);
    printf("=====test_sm2_from_hex passed\n");
}

void test_sm2_long(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm2_long\n");
    int ret = 0;

    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "Thinta_Application", "111111", &happ);

    u8 *pubkey, *prikey;
    u64 pubkey_len, prikey_len;

    u8 keypair[] = {
        // x
        0x19, 0x79, 0x5d, 0xf7, 0x01, 0xf3, 0x9d, 0x1f, 0xb2, 0x20, 0xc4, 0x5f, 0xa7, 0xfa, 0x4e, 0xbf,
        0xad, 0xd1, 0x70, 0x25, 0x37, 0xb9, 0x46, 0xcd, 0x3d, 0x48, 0x04, 0xb3, 0x7f, 0xbc, 0x3e, 0xa5,
        // y
        0x2b, 0x2c, 0xee, 0xd6, 0xcc, 0x04, 0x2b, 0x5b, 0xbb, 0x56, 0x8d, 0xed, 0x3b, 0x36, 0x73, 0xf2,
        0x88, 0xe1, 0x9c, 0xc4, 0x9a, 0xe3, 0xc3, 0x50, 0xd2, 0xb8, 0x09, 0x03, 0xd8, 0x6d, 0x91, 0x2c,
        // d
        0x3f, 0x91, 0x68, 0xe8, 0x6d, 0x2a, 0xac, 0xaa, 0x2c, 0x81, 0xd8, 0xba, 0x24, 0x9b, 0xc9, 0x5a,
        0x60, 0xe0, 0x47, 0x50, 0xa2, 0xee, 0xaa, 0x63, 0x26, 0x2b, 0x54, 0xc4, 0x75, 0x51, 0xb8, 0xdc};

    pubkey = keypair;
    pubkey_len = 64;
    prikey = keypair + 64;
    prikey_len = 32;

    zzcrypt_sm2_import_key(hdev, happ, prikey, pubkey);

    size_t data_len = 256;
    u8 data[256];
    for (size_t i = 0; i < data_len; i++) {
        data[i] = i % 256;
    }
    u8 *enc_data;
    size_t enc_len;
    ret = zzcrypt_sm2_encrypt(hdev, pubkey, data, data_len, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("enc_data", enc_data, enc_len);

    u8 *dec_data;
    size_t dec_len;
    ret = zzcrypt_sm2_decrypt(hdev, prikey, enc_data, enc_len, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("dec_data", dec_data, dec_len);

    size_t remain = data_len;
    while (remain > 0) {
        size_t len = remain > 16 ? 16 : remain;
        assert(memcmp(data + data_len - remain, dec_data + data_len - remain, len) == 0);
        remain -= len;
    }
    printf("=====test_sm2_long passed\n");
}

void test_sm2_gw(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm2_gw\n");
    int ret = 0;

    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "Thinta_Application", "111111", &happ);

    u8 *pubkey, *prikey;
    size_t pubkey_len, prikey_len;

    ret = zzhex_hex_to_bin("553782b0feb2db3ad00057453b268bde24cde6cc779c40ba74baa2016b8c41f1", &prikey, &prikey_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pri key", prikey, prikey_len);
    ret = zzhex_hex_to_bin("0c7e0ac73899d4e8006dc7f977cfc3e9314f0001816c3ebfcbc03f58df5ad76129f3133cf2d209df31ba81422384c1d613c416afa36a65b0bd791d5ea1cf5ae8", &pubkey, &pubkey_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pub key", pubkey, pubkey_len);
    assert(prikey_len == 32);
    assert(pubkey_len == 64);

    u8 data[3] = {0x11, 0x22, 0x33};
    u8 *enc_data;
    size_t enc_len;
    zzcrypt_sm2_encrypt(hdev, pubkey, data, 3, &enc_data, &enc_len);
    zzhex_print_data_hex("enc_data", enc_data, enc_len);

    u8 *dec_data;
    size_t dec_len;
    zzcrypt_sm2_decrypt(hdev, prikey, enc_data, enc_len, &dec_data, &dec_len);
    zzhex_print_data_hex("dec_data", dec_data, dec_len);

    assert(memcmp(data, dec_data, 3) == 0);
    printf("=====test_sm2_from_hex passed\n");
}

void test_sm4_gw(zzcrypt_devhandle_p hdev) {
    printf("=====test_sm4_gw\n");
    unsigned char key[16] = {0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d, 0x72};
    unsigned char enc_data[32] = {0x01, 0x6b, 0xde, 0x3b, 0x27, 0x1a, 0x22, 0x2c, 0x39, 0x21, 0x34, 0xbb, 0x6b, 0xe1, 0x0e, 0x74, 0x4a, 0x67, 0xc7, 0x92, 0xd4, 0xe0, 0x62, 0x8f, 0x67, 0x87, 0xf5, 0x1b, 0xa3, 0xc9, 0x31, 0xbc};
    zzcrypt_keyhandle_p hkey;
    int ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    zzcrypt_cipherp_param_t param;
    param.algorithm = zzcrypt_algorithm_sm4ecb;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_none;
    ret = zzcrypt_sm4_decrypt_init(hkey, param);
    assert(ret == ZZECODE_OK);

    u8 *dec_data;
    size_t dec_len;

    ret = zzcrypt_sm4_decrypt_push(hkey, enc_data, 32);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_sm4_decrypt_peek(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("peek decrypted data", dec_data, dec_len);

    ret = zzcrypt_sm4_decrypt_pop(hkey, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("pop  decrypted data", dec_data, dec_len);

    printf("%s\n", dec_data);
}

void test_file(zzcrypt_devhandle_p hdev) {
    int ret;
    printf("=====test_file\n");
    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "Thinta_Application", "111111", &happ);

    char *filename = "testfile";
    u32 data_len = 2222;
    u8 data[2222];
    for (int i = 0; i < data_len; ++i) {
        data[i] = i % 0xff;
    }

    u8 *read_data;
    size_t read_len;

    ret = zzcrypt_file_remove(happ, filename);
    assert(ret == ZZECODE_OK || ret == ZZECODE_FILE_NOT_EXIST);

    ret = zzcrypt_file_read(happ, filename, &read_data, &read_len);
    assert(ret == ZZECODE_FILE_NOT_EXIST);

    ret = zzcrypt_file_write(happ, filename, data, data_len);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_file_write(happ, filename, data, data_len);
    assert(ret == ZZECODE_FILE_ALREADY_EXIST);

    ret = zzcrypt_file_read(happ, filename, &read_data, &read_len);
    assert(ret == ZZECODE_OK);
    assert(data_len == read_len);
    assert(memcmp(data, read_data, read_len) == 0);

    ret = zzcrypt_file_remove(happ, filename);
    assert(ret == ZZECODE_OK);

    ret = zzcrypt_file_read(happ, filename, &read_data, &read_len);
    assert(ret == ZZECODE_FILE_NOT_EXIST);

    printf("=====test_file passed\n");
}

void test_loadpem(zzcrypt_devhandle_p hdev) {
    int ret;
    printf("=====import_key_from_pem\n");
    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "Thinta_Application", "111111", &happ);

    u8 *pubkey = NULL;
    u8 *prikey = NULL;
    {
        const char *filename = "private_key.pem";
        ret = zzcrypt_sm2_import_key_from_file(hdev, happ, filename, &prikey);
        assert(ret == ZZECODE_OK);
    }

    {
        const char *filename = "certificate.crt";
        ret = zzcrypt_sm2_get_pubkey_from_file(hdev, happ, filename, &pubkey);
        assert(ret == ZZECODE_OK);
    }

    u8 data[] = {0x11, 0x22, 0x33};
    size_t data_len = sizeof(data);

    u8 *enc_data;
    size_t enc_len;
    ret = zzcrypt_sm2_encrypt(hdev, pubkey, data, data_len, &enc_data, &enc_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("enc_data", enc_data, enc_len);

    u8 *dec_data;
    size_t dec_len;
    ret = zzcrypt_sm2_decrypt(hdev, prikey, enc_data, enc_len, &dec_data, &dec_len);
    assert(ret == ZZECODE_OK);
    zzhex_print_data_hex("dec_data", dec_data, dec_len);

    assert(dec_len == data_len);
    assert(memcmp(data, dec_data, dec_len) == 0);
    printf("=====import_key_from_pem passed\n");
}

void test_load_gw_pubkey(zzcrypt_devhandle_p hdev) {
    int ret;
    printf("=====import_key_from_pem\n");
    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "Thinta_Application", "111111", &happ);

    char *filenames;
    ret = zzcrypt_file_list(happ, &filenames);
    assert(ret == ZZECODE_OK);
    printf("filenames: %s\n", filenames);

    {
        u8 *pubkey = NULL;
        const char *filename = "certificate.crt";
        ret = zzcrypt_sm2_get_pubkey_from_file(hdev, happ, filename, &pubkey);
        assert(ret == ZZECODE_OK);
    }

    u8 *pubkey = NULL;
    {
        const char *filename = "gw_certificate.crt";
        ret = zzcrypt_sm2_get_pubkey_from_file(hdev, happ, filename, &pubkey);
        assert(ret == ZZECODE_OK);
    }

    zzhex_print_data_hex("enc_data", pubkey, 64);
}

void test_device_remove(zzcrypt_devhandle_p hdev) {
    while (true) {
        int ret = zzcrypt_dev_exists(hdev);
        printf("%d\n", ret);
        dosleep(1000);
    }
}

int main() {
    int ret;

    zzcrypt_devhandle_p hdev;
    ret = zzcrypt_init(&hdev, stderr);
    assert(ret == ZZECODE_OK);

    zzcrypt_devinfo_t info;
    ret = zzcrypt_devinfo(hdev, &info);
    assert(ret == ZZECODE_OK);
    printf("dev serial number: %s\n", info.serial_number);
    printf("dev issuer: %s\n", info.issuer);
    printf("dev space: %u/%u\n", info.space_avali, info.space_total);

    // test_sm4_gw(hdev);
    // test_sm4_ecb(hdev);
    // test_sm4_ecb_padding(hdev);
    // test_sm4_ecb_padding_zero(hdev);
    // test_sm4_ecb_padding_pkcs5(hdev);
    // test_sm4_cbc(hdev);
    // test_sm4_ecb_17(hdev);
    // test_sm4_ecb_long(hdev);
    // test_sm2(hdev);
    // test_sm2_from_hex(hdev);
    // test_sm2_gw(hdev);
    // test_sm2_long(hdev);
    // test_file(hdev);
    // test_loadpem(hdev);
    // test_load_gw_pubkey(hdev);
    test_device_remove(hdev);

    pasue_on_exit();
    return 0;
}
