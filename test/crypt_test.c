#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <zzutil/errmsg.h>
#include <zzutil/zzcrypt.h>
#include <zzutil/zzhex.h>
#include <zzutil/basetype.h>

#include "testutil.h"

void test_sm4_ecb(zzcrypt_devhandle_p hdev) {
    int ret;
    u8 key[16] = {
        0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec
    };
    u8 data[16] = {
        0x5f,0xe9,0x7c,0xcd,0x58,0xfe,0xd7,0xab,0x41,0xf7,0x1e,0xfb,0xfd,0xe7,0xe1,0x46
    };
    u8 enc_data_expect[] = {
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
    printf("=====test_sm4_ecb passed\n");
}

void test_sm4_ecb_padding(zzcrypt_devhandle_p hdev) {
    int ret;
    u8 key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    u8 data[] = {0x11,0x22,0x33};   //1122330d0d0d0d0d0d0d0d0d0d0d0d0d
    u8 enc_data_expect[] = {0x2C,0xFE,0xC5,0x55,0xF0,0xE7,0x0B,0x7A,0xC1,0xD2,0x0A,0xC3,0xD2,0xC5,0x85,0x11};

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
    printf("=====test_sm4_ecb_padding passed\n");
}

void test_sm4_ecb_padding_zero(zzcrypt_devhandle_p hdev) {
    u8 key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    u8 data[] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};//11223344556677889907070707070707
    u8 enc_data_expect[] = {0xA3,0x5C,0xC2,0xB1,0x54,0xD6,0xE8,0xAB,0x9D,0x7C,0xA6,0xB9,0xC3,0x76,0x7D,0x0C};

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
    printf("=====test_sm4_ecb_padding2 passed\n");
}

void test_sm4_ecb_padding_pkcs5(zzcrypt_devhandle_p hdev) {
    int ret = 0;
    u8 key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    u8 data[] = {0x5f,0xe9,0x7c,0xcd,0x58,0xfe,0xd7,0xab,0x41,0xf7,0x1e,0xfb,0xfd,0xe7,0xe1,0x46};
    u8 result[] = {0x56,0xda,0x23,0xe2,0x5f,0xa7,0xcd,0x82,0x5d,0x51,0xc2,0x20,0xf5,0x98,0x09,0x0b,
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
    printf("=====test_sm4_ecb_pkcs5 passed\n");

}

void test_sm4_cbc(zzcrypt_devhandle_p hdev) {
    int ret = 0;
    u8  key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    u8  data[] = {0x5f,0xe9,0x7c,0xcd,0x58,0xfe,0xd7,0xab,0x41,0xf7,0x1e,0xfb,0xfd,0xe7,0xe1,0x46};
    u8  result[] = {0x56,0xda,0x23,0xe2,0x5f,0xa7,0xcd,0x82,0x5d,0x51,0xc2,0x20,0xf5,0x98,0x09,0x0b,
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
    printf("=====test_sm4_cbc passed\n");
}

void test_sm4_ecb_long_message() {}

void test_sm2(zzcrypt_devhandle_p hdev) {
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

    u8 keypair[] = {
        //x
        0x19,0x79,0x5d,0xf7,0x01,0xf3,0x9d,0x1f,0xb2,0x20,0xc4,0x5f,0xa7,0xfa,0x4e,0xbf,
        0xad,0xd1,0x70,0x25,0x37,0xb9,0x46,0xcd,0x3d,0x48,0x04,0xb3,0x7f,0xbc,0x3e,0xa5,
        //y
        0x2b,0x2c,0xee,0xd6,0xcc,0x04,0x2b,0x5b,0xbb,0x56,0x8d,0xed,0x3b,0x36,0x73,0xf2,
        0x88,0xe1,0x9c,0xc4,0x9a,0xe3,0xc3,0x50,0xd2,0xb8,0x09,0x03,0xd8,0x6d,0x91,0x2c,
        //d
        0x3f,0x91,0x68,0xe8,0x6d,0x2a,0xac,0xaa,0x2c,0x81,0xd8,0xba,0x24,0x9b,0xc9,0x5a,
        0x60,0xe0,0x47,0x50,0xa2,0xee,0xaa,0x63,0x26,0x2b,0x54,0xc4,0x75,0x51,0xb8,0xdc
    };

    pubkey = keypair;
    pubkey_len = 64;
    prikey = keypair + 64;
    prikey_len = 32;

    // u8 data[3] = {0x11,0x22,0x33};
    u8 data[3] = {0x11,0x22,0x33};
    u8 *enc_data;
    size_t enc_len;
    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "zzmaintenancetool", "87654321", &happ);
    zzcrypt_sm2_import_key(hdev, happ, prikey, pubkey);
    zzcrypt_sm2_encrypt(hdev, pubkey, data, 3, &enc_data, &enc_len);
    zzhex_print_data_hex("enc_data", enc_data, enc_len);

    u8 *dec_data;
    size_t dec_len;
    zzcrypt_sm2_decrypt(hdev, prikey, enc_data, enc_len, &dec_data, &dec_len);
    zzhex_print_data_hex("dec_data", dec_data, dec_len);

    assert(memcmp(data, dec_data, 3) == 0);
    printf("=====test_sm2 passed\n");
}

void test_sm2_from_hex(zzcrypt_devhandle_p hdev) {
    int ret = 0;

    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "zzmaintenancetool", "87654321", &happ);

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

    u8 data[3] = {0x11,0x22,0x33};
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
    int ret = 0;

    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "zzmaintenancetool", "87654321", &happ);

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

    u8 keypair[] = {
        //x
        0x19,0x79,0x5d,0xf7,0x01,0xf3,0x9d,0x1f,0xb2,0x20,0xc4,0x5f,0xa7,0xfa,0x4e,0xbf,
        0xad,0xd1,0x70,0x25,0x37,0xb9,0x46,0xcd,0x3d,0x48,0x04,0xb3,0x7f,0xbc,0x3e,0xa5,
        //y
        0x2b,0x2c,0xee,0xd6,0xcc,0x04,0x2b,0x5b,0xbb,0x56,0x8d,0xed,0x3b,0x36,0x73,0xf2,
        0x88,0xe1,0x9c,0xc4,0x9a,0xe3,0xc3,0x50,0xd2,0xb8,0x09,0x03,0xd8,0x6d,0x91,0x2c,
        //d
        0x3f,0x91,0x68,0xe8,0x6d,0x2a,0xac,0xaa,0x2c,0x81,0xd8,0xba,0x24,0x9b,0xc9,0x5a,
        0x60,0xe0,0x47,0x50,0xa2,0xee,0xaa,0x63,0x26,0x2b,0x54,0xc4,0x75,0x51,0xb8,0xdc
    };

    pubkey = keypair;
    pubkey_len = 64;
    prikey = keypair + 64;
    prikey_len = 32;

    zzcrypt_sm2_import_key(hdev, happ, prikey, pubkey);

    // u8 data[3] = {0x11,0x22,0x33};
    // u8 data[67] = {0x7b,0x22,0x75,0x6b,0x65,0x79,0x5f,0x6d,0x61,0x63,0x22,0x3a,0x22,0x34,0x34,0x3a,0x41,0x33,0x3a,0x42,0x42,0x3a,0x35,0x35,0x3a,0x38,0x46,0x3a,0x42,0x36,0x22,0x2c,0x22,0x75,0x6b,0x65,0x79,0x5f,0x73,0x65,0x72,0x69,0x61,0x6c,0x6e,0x6f,0x22,0x3a,0x22,0x34,0x44,0x33,0x38,0x34,0x36,0x33,0x35,0x33,0x37,0x30,0x36,0x33,0x38,0x32,0x45,0x22,0x7d,};
    u8 data[] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
    };
    size_t data_len = 20;
    u8 *enc_data;
    size_t enc_len;
    zzcrypt_sm2_encrypt(hdev, pubkey, data, data_len, &enc_data, &enc_len);
    zzhex_print_data_hex("enc_data", enc_data, enc_len);

    u8 *dec_data;
    size_t dec_len;
    zzcrypt_sm2_decrypt(hdev, prikey, enc_data, enc_len, &dec_data, &dec_len);
    zzhex_print_data_hex("dec_data", dec_data, dec_len);

    assert(memcmp(data, dec_data, data_len) == 0);
    printf("=====test_sm2 passed\n");
}

void test_sm2_gw(zzcrypt_devhandle_p hdev) {
    int ret = 0;

    zzcrypt_apphandle_p happ = NULL;
    zzcrypt_init_app(hdev, "zzmaintenancetool", "87654321", &happ);

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

    u8 data[3] = {0x11,0x22,0x33};
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

    test_sm2(hdev);
    test_sm2_from_hex(hdev);
    test_sm2_long(hdev);
    test_sm2_gw(hdev);

    pasue_on_exit();
    return 0;
}
