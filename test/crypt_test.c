#include <stdio.h>
#include <assert.h>
#include <stdint.h>

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
    uint8_t res_data[] = {
        0x56,0xda,0x23,0xe2,0x5f,0xa7,0xcd,0x82,0x5d,0x51,0xc2,0x20,0xf5,0x98,0x09,0x0b
    };

    zzcrypt_keyhandle_p hkey;
    ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    block_cipherp_param_t param;
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
}

void test_sm4_ecb_padding(zzcrypt_devhandle_p hdev) {
    int ret;
    uint8_t key[] = {0x77,0x7f,0x23,0xc6,0xfe,0x7b,0x48,0x73,0xdd,0x59,0x5c,0xff,0xf6,0x5f,0x58,0xec};
    uint8_t data[] = {0x11,0x22,0x33};   //1122330d0d0d0d0d0d0d0d0d0d0d0d0d
    uint8_t gdb_data[] = {0x2C,0xFE,0xC5,0x55,0xF0,0xE7,0x0B,0x7A,0xC1,0xD2,0x0A,0xC3,0xD2,0xC5,0x85,0x11};

    zzcrypt_keyhandle_p hkey;
    ret = zzcrypt_sm4_import_key(hdev, key, &hkey);
    assert(ret == ZZECODE_OK);

    block_cipherp_param_t param;
    param.iv = NULL;
    param.iv_len = 0;
    param.padding_type = zzcrypt_padding_pkcs7;
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
}

void test_sm4_ecb_padding2() {}

int main() {
    int ret;

    zzcrypt_devhandle_p hdev;
    ret = zzcrypt_init(&hdev, stderr);
    assert(ret == ZZECODE_OK);

    test_sm4_ecb_padding(hdev);

    return 0;
}
