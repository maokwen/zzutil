#include "zzutil/zzcrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _UNIX
#include <unistd.h>
#include <dlfcn.h>
#include <mntent.h>
#include <sys/stat.h>
#endif

#define OPENSSL_API_COMPAT 30000
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include <skf.h>

#include <zzutil/zzcrypt.h>
#include <zzutil/errmsg.h>

#include "common/helper.h"

/************************************************************
 * Declears
 ************************************************************/

typedef struct _zzcrypt_devhandle hdev_t;
typedef struct _zzcrypt_keyhandle hkey_t;
typedef struct _zzcrypt_apphandle happ_t;
typedef struct _zzcrypt_ctnhandle ctn_t;
typedef struct _zzcrypt_cipherp_param cparam_t;
typedef HANDLE skf_handle_t;

static PSKF_FUNCLIST FunctionList;
static bool is_initialized = false;
static const u32 DeviceLockTimeout = 5000;
static FILE *log_output = NULL;
static const size_t VectorBufInitSize = 256;

static bool load_library(const char *exec_path);
static size_t sm2_sizeof_encoded_data(size_t cipher_len);
static void print_device_info(skf_handle_t hdev);
static bool skf_error(const char *msg, int ret);
static BLOCKCIPHERPARAM gen_block_cipher_param(const cparam_t *param);
static void realloc_vector_buffer(hkey_t *hkey, size_t new_size);
static u8 rand_none_zero_byte();
static size_t padding_zero(hkey_t *hkey);
static size_t padding_pkcs7(hkey_t *hkey);
static size_t unpadding_zero(hkey_t *hkey);
static size_t unpadding_pkcs7(hkey_t *hkey);
static u8 *datdat(const u8 *dat1, size_t len1, const u8 *dat2, size_t len2);
static bool get_exec_path(char *buf, size_t len);

#ifdef _UNIX
static char *get_device_from_mounts(dev_t dev);
static void read_sysfs_file(const char *device, const char *filename, char *result);
static int get_device_numbers(const char *dev, int *major, int *minor);
#endif

#define LOG(fmt, ...)                              \
    if (log_output) {                              \
        fprintf(log_output, "zzcrypt ");           \
        fprintf(log_output, (fmt), ##__VA_ARGS__); \
    }

/************************************************************
 * Public functions
 ************************************************************/

struct _zzcrypt_devhandle {
    skf_handle_t skf_handle;
    bool is_initialized;
    char dev_name[256];
    char exec_path[256];
};

struct _zzcrypt_keyhandle {
    skf_handle_t skf_handle;
    bool is_initialized;
    // vector buffer for sm4 encryption/decryption
    u8 *buf;
    size_t buf_len;
    u8 *data_ptr;
    u32 data_len;
    // for padding
    int padding_type;
    u32 block_size;
    u32 src_len;
    u8 *padding_buf;
};

struct _zzcrypt_apphandle {
    skf_handle_t skf_handle;
    bool is_initialized;
    u32 retry;
    char app_name[128];
};

struct _zzcrypt_ctnhandle {
    HCONTAINER skf_handle;
    bool is_initialized;
};

int zzcrypt_init(hdev_t **hdev, FILE *log) {
    int ret;
    char devices[512] = {0};
    char app_name_buf[128];
    u32 devices_size = sizeof(devices);

    hdev_t *h = malloc(sizeof(hdev_t));
    h->is_initialized = false;
    *hdev = h;

    log_output = log;

    if (is_initialized) {
        return ZZECODE_CRYPT_ALREADY_INIT;
    }

    if (!get_exec_path(h->exec_path, sizeof(h->exec_path))) {
        return false;
    }

    if (!load_library(h->exec_path)) {
        LOG("failed to load library\n");
        return ZZECODE_OS_ERROR;
    }

    /* get device name */
    ret = FunctionList->SKF_EnumDev(1, NULL, &devices_size);
    if (skf_error("SKF_EnumDev", ret)) {
        return ZZECODE_SKF_ERR;
    }

    if (devices_size == 0) {
        return ZZECODE_CRYPT_NO_DEVICE;
    }

    /* get device name */
    ret = FunctionList->SKF_EnumDev(1, devices, &devices_size);
    if (skf_error("SKF_EnumDev", ret)) {
        return ZZECODE_SKF_ERR;
    }

    if (strlen((char *)devices) == 0) {
        return ZZECODE_CRYPT_NO_DEVICE;
    }

    strcpy(h->dev_name, devices);

    /* connect device */
    ret = FunctionList->SKF_ConnectDev(devices, &h->skf_handle);
    if (skf_error("SKF_ConnectDev", ret)) {
        return ZZECODE_SKF_ERR;
    }

    /* get ukey DevAuthAlgId */ DISABLE {
        print_device_info((*hdev)->skf_handle);
    }

    /* enmu all app */
    u32 len = sizeof(app_name_buf);
    ret = FunctionList->SKF_EnumApplication((*hdev)->skf_handle, app_name_buf, &len);
    if (skf_error("SKF_EnumApplication", ret)) {
        return ZZECODE_SKF_ERR;
    }

    /* lock device */ DISABLE {
        ret = FunctionList->SKF_LockDev((*hdev)->skf_handle, DeviceLockTimeout);
        if (skf_error("SKF_LockDev", ret)) {
            return ZZECODE_SKF_ERR;
        }
    }

    (*hdev)->is_initialized = true;
    is_initialized = true;

    return ZZECODE_OK;
}

int zzcrypt_init_app(const hdev_t *hdev, const char *app_name, const char *pin, happ_t **happ) {
    int ret;

    // call SKF_OpenApplication will crash the stack
    char pin_buf[128];
    strcpy(pin_buf, pin);

    if (!hdev->is_initialized) {
        return ZZECODE_NO_INIT;
    }

    happ_t *app = malloc(sizeof(zzcrypt_apphandle_t));
    strcpy(app->app_name, app_name);
    *happ = app;
    app->is_initialized = false;
    ret = FunctionList->SKF_OpenApplication(hdev->skf_handle, app->app_name, &app->skf_handle);
    if (skf_error("SKF_OpenApplication", ret)) {
        return ZZECODE_SKF_ERR;
    }

    ret = FunctionList->SKF_VerifyPIN(app->skf_handle, USER_TYPE, (char *)pin_buf, &app->retry);
    if (ret == SAR_PIN_INCORRECT || ret == SAR_PIN_INVALID) {
        return ZZECODE_PIN_INCORRECT;
    } else if (ret == SAR_PIN_LOCKED) {
        return ZZECODE_PIN_LOCKED;
    } else if (skf_error("SKF_VerifyPIN", ret)) {
        return ZZECODE_SKF_ERR;
    }

    app->is_initialized = true;

    return ZZECODE_OK;
}

int zzcrypt_release_app(happ_t *happ) {
    if (happ == NULL) {
        return ZZECODE_DOUBLE_RELEASE;
    }
    u32 ret;
    ret = FunctionList->SKF_ClearSecureState(happ->skf_handle);
    if (skf_error("SKF_ClearSecureState", ret)) {
        return ZZECODE_SKF_ERR;
    }
    ret = FunctionList->SKF_CloseApplication(happ->skf_handle);
    if (skf_error("SKF_CloseApplication", ret)) {
        return ZZECODE_SKF_ERR;
    }
    free(happ);
    return ZZECODE_OK;
}

int zzcrypt_sm2_import_key(const hdev_t *hdev, const happ_t *happ, const u8 *prikey, const u8 *pubkey) {
    int ret;
    if (!happ->is_initialized || !hdev->is_initialized) {
        return ZZECODE_NO_INIT;
    }

    /**
     *how to import sm2 keypair:
     *1\prepare sm2 keypair into buf
     *2\prepare the struct PENVELOPEDKEYBLOB :env
     *3\get the pubkey form ukey, copy pubkey to env
     *4\use sm1 algo encrypt prikey and then copy to env.cbEncryptedPriKey
     *5\use sm2 pubkey encrypt sm1 key ,and then copy to env.ECCCipherBlob
     *6\call SKF_ImportECCKeyPair
     */
    HCONTAINER hctn = NULL;

    // 1. create conatiner
    ret = FunctionList->SKF_CreateContainer(happ->skf_handle, "ZZSM2", &hctn);
    if (ret) { // may exist
        ret = FunctionList->SKF_OpenContainer(happ->skf_handle, "ZZSM2", &hctn);
        if (skf_error("SKF_OpenContainer", ret)) {
            return ZZECODE_SKF_ERR;
        }
    }

    // 2. get the pubkey form ukey, copy pubkey to env
    u32 ctn_type = 0;
    ret = FunctionList->SKF_GetContainerType(hctn, &ctn_type);
    if (skf_error("SKF_GetContainerType", ret)) {
        return ZZECODE_SKF_ERR;
    }

    u32 pubkey_len = (u32)sizeof(ECCPUBLICKEYBLOB);
    ECCPUBLICKEYBLOB pubkey_blob;
    memset(&pubkey_blob, 0, pubkey_len);
    ret = FunctionList->SKF_ExportPublicKey(hctn, false, (u8 *)&pubkey_blob, &pubkey_len);
    if (ret == 0x0A00001B && ctn_type == CTNF_ECC && pubkey_blob.BitLen == 256) { // already import
        return ZZECODE_ALREADY_IMPORT;
    }

    ret = FunctionList->SKF_ExportPublicKey(hctn, true, (u8 *)&pubkey_blob, &pubkey_len);
    if (ret == 0x0A00001B) {
        ret = FunctionList->SKF_GenECCKeyPair(hctn, SGD_SM2_1, &pubkey_blob);
        if (skf_error("SKF_GenECCKeyPair", ret)) {
            return ZZECODE_SKF_ERR;
        }
    } else if (skf_error("SKF_ExportPublicKey", ret)) {
        return ZZECODE_SKF_ERR;
    }

    // 3. use sm1 algo encrypt prikey and then copy to env.cbEncryptedPriKey
    size_t buf_len = sizeof(ENVELOPEDKEYBLOB) + sm2_sizeof_encoded_data(16);
    PENVELOPEDKEYBLOB env_blob = malloc(buf_len);
    memset(env_blob, 0, buf_len);
    env_blob->Version = 0x00000001;
    env_blob->ulSymmAlgID = SGD_SM1_ECB;
    env_blob->ulBits = 256;
    env_blob->PubKey.BitLen = 256;
    memcpy(env_blob->PubKey.XCoordinate + 32, pubkey, 32);
    memcpy(env_blob->PubKey.YCoordinate + 32, pubkey + 32, 32);
    u8 key[16] = {0x47, 0x50, 0x42, 0x02, 0x20, 0x3F, 0xE1, 0x92, 0x66, 0x2A, 0xCB, 0xD2, 0x9D, 0x11, 0x22, 0x33};
    HANDLE hkey = NULL;
    ret = FunctionList->SKF_SetSymmKey(hdev->skf_handle, key, SGD_SM1_ECB, &hkey);
    if (skf_error("SKF_SetSymmKey", ret)) {
        free(env_blob);
        return ZZECODE_SKF_ERR;
    }
    BLOCKCIPHERPARAM bp;
    memset(&bp, 0, sizeof(BLOCKCIPHERPARAM));
    ret = FunctionList->SKF_EncryptInit(hkey, bp);
    if (skf_error("SKF_EncryptInit", ret)) {
        free(env_blob);
        return ZZECODE_SKF_ERR;
    }
    u32 enclen = 128;
    ret = FunctionList->SKF_Encrypt(hkey, (u8 *)prikey, 32, env_blob->cbEncryptedPriKey + 32, &enclen);
    if (skf_error("SKF_Encrypt", ret)) {
        free(env_blob);
        return ZZECODE_SKF_ERR;
    }

    // 4. use sm2 pubkey encrypt sm1/sm4 key, and then copy to env.ECCCipherBlob
    ret = FunctionList->SKF_ExtECCEncrypt(hdev->skf_handle, &pubkey_blob, key, 16, &env_blob->ECCCipherBlob);
    if (skf_error("SKF_ExtECCEncrypt", ret)) {
        free(env_blob);
        return ZZECODE_SKF_ERR;
    }

    // 5. inport keypair
    ret = FunctionList->SKF_ImportECCKeyPair(hctn, env_blob);
    if (skf_error("SKF_ImportECCKeyPair", ret)) {
        free(env_blob);
        return ZZECODE_SKF_ERR;
    }

    free(env_blob);
    return ZZECODE_OK;
}

int zzcrypt_sm2_encrypt(const hdev_t *hdev, const u8 *pubkey, const u8 *data, size_t len, u8 **enc_data, size_t *enc_len) {
    int ret;
    if (!hdev->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    ECCPUBLICKEYBLOB pubkey_blob;
    memset(&pubkey_blob, 0, sizeof(ECCPUBLICKEYBLOB));
    pubkey_blob.BitLen = 256;
    memcpy(pubkey_blob.XCoordinate + 32, pubkey, 32);
    memcpy(pubkey_blob.YCoordinate + 32, pubkey + 32, 32);

    // u8 *p = malloc(100);
    size_t buf_len = sm2_sizeof_encoded_data(len);
    PECCCIPHERBLOB res_blob = malloc(buf_len);
    memset(res_blob, 0, buf_len);
    ret = FunctionList->SKF_ExtECCEncrypt(hdev->skf_handle, &pubkey_blob, (u8 *)data, (u32)len, res_blob);
    if (skf_error("SKF_ExtECCEncrypt", ret)) {
        free(res_blob);
        return ZZECODE_SKF_ERR;
    }
    // u8 *q = malloc(100);

    size_t real_len = sm2_sizeof_encoded_data((size_t)(res_blob->CipherLen));
    *enc_len = real_len;
    *enc_data = malloc(real_len);
    memcpy(*enc_data, res_blob, real_len);
    free(res_blob);

    return ZZECODE_OK;
}

int zzcrypt_sm2_decrypt(const hdev_t *hdev, const u8 *prikey, const u8 *enc_data, size_t enc_len, u8 **data, size_t *len) {
    int ret;

    if (!hdev->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    ECCPRIVATEKEYBLOB prikey_blob;
    memset(&prikey_blob, 0, sizeof(ECCPRIVATEKEYBLOB));
    prikey_blob.BitLen = 256;
    memcpy(prikey_blob.PrivateKey + 32, prikey, 32);

    PECCCIPHERBLOB p_enc = (PECCCIPHERBLOB)malloc(sm2_sizeof_encoded_data(enc_len));
    p_enc->CipherLen = (u32)enc_len;
    memcpy(p_enc, enc_data, enc_len);

    u8 *buf = malloc(enc_len); // typically, the decrypted data is not longer than the encrypted data
    u32 de_len = (u32)enc_len;
    ret = FunctionList->SKF_ExtECCDecrypt(hdev->skf_handle, &prikey_blob, p_enc, buf, &de_len);
    if (skf_error("SKF_ExtECCDecrypt", ret)) {
        free(buf);
        free(p_enc);
        return ZZECODE_SKF_ERR;
    }

    *len = de_len;
    *data = malloc(de_len);
    memcpy(*data, buf, de_len);
    free(buf);

    return ZZECODE_OK;
}

int zzcrypt_sm4_import_key(const hdev_t *hdev, const u8 *key, hkey_t **hkey) {
    int ret;

    hkey_t *h = malloc(sizeof(hkey_t));
    h->is_initialized = false;
    *hkey = h;
    ret = FunctionList->SKF_SetSymmKey(hdev->skf_handle, (u8 *)key, SGD_SMS4_ECB, &h->skf_handle);
    if (skf_error("SKF_SetSymmKey", ret)) {
        return ZZECODE_SKF_ERR;
    }

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_init(hkey_t *hkey, cparam_t param) {
    int ret;

    if (hkey->is_initialized) {
        return ZZECODE_CRYPT_ALREADY_INIT;
    }

    BLOCKCIPHERPARAM p = gen_block_cipher_param(&param);
    ret = FunctionList->SKF_EncryptInit(hkey->skf_handle, p);
    if (skf_error("SKF_EncryptInit", ret)) {
        return ZZECODE_SKF_ERR;
    }

    hkey->buf = malloc(VectorBufInitSize);
    hkey->buf_len = VectorBufInitSize;
    hkey->data_ptr = hkey->buf;
    hkey->data_len = 0;

    hkey->padding_type = param.padding_type;
    hkey->src_len = 0;
    hkey->block_size = 16; // due to limit of skf impl, only 16 is supported for none padding
    hkey->padding_buf = NULL;

    hkey->is_initialized = true;

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_push(hkey_t *hkey, const u8 *data, size_t len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    // check upcomming length of data
    u32 new_len = 0;
    DISABLE {
        // NOTE: didn't fucking work (for impl of current skf library)
        //       use the code blow will break the crpyto process - for no reason.
        ret = FunctionList->SKF_EncryptUpdate(hkey->skf_handle, (u8 *)data, (u32)len, NULL, &new_len);
        if (skf_error("SKF_EncryptUpdate", ret)) {
            return ZZECODE_SKF_ERR;
        }
        if (new_len == 0) {
            new_len = (u32)len;
        }
    }
    else {
        // assume that the length of encrypted data is less than twice of the original data
        // that means new_len is not greater than len*2
        if (len > hkey->block_size) {
            new_len = (u32)len * 2;
        } else {
            new_len = (u32)(hkey->block_size) * 2;
        }
    }

    // if buffer is not enough, realloc it
    size_t new_size = hkey->data_len + new_len;
    realloc_vector_buffer(hkey, new_size);

    // push data to buffer
    // u32 left = hkey->buf_len - hkey->data_len;
    new_len = 0;
    ret = FunctionList->SKF_EncryptUpdate(hkey->skf_handle, (u8 *)data, (u32)len, hkey->data_ptr, &new_len);
    if (skf_error("SKF_EncryptUpdate", ret)) {
        return ZZECODE_SKF_ERR;
    }
    hkey->src_len += len;
    hkey->data_len += new_len;
    hkey->data_ptr += new_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_peek(const hkey_t *hkey, u8 **enc_data, size_t *enc_len) {
    if (!hkey->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    *enc_data = malloc(hkey->data_len);
    memcpy(*enc_data, hkey->buf, hkey->data_len);
    *enc_len = hkey->data_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_pop(hkey_t *hkey, u8 **enc_data, size_t *enc_len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    // padding data if last block is not full
    {
        u32 new_len = 0;
        if (hkey->padding_type == zzcrypt_padding_zero) {
            u32 remain = padding_zero(hkey);
            if (remain != 0) {
                ret = FunctionList->SKF_EncryptUpdate(hkey->skf_handle, hkey->padding_buf, remain, hkey->data_ptr, &new_len);
                if (skf_error("SKF_EncryptUpdate", ret)) {
                    return ZZECODE_SKF_ERR;
                }
                hkey->data_len += new_len;
                hkey->data_ptr += new_len;
            }
        } else if (hkey->padding_type == zzcrypt_padding_pkcs7) {
            u32 remain = padding_pkcs7(hkey);
            if (remain != 0) {
                ret = FunctionList->SKF_EncryptUpdate(hkey->skf_handle, hkey->padding_buf, remain, hkey->data_ptr, &new_len);
                if (skf_error("SKF_EncryptUpdate", ret)) {
                    return ZZECODE_SKF_ERR;
                }
                hkey->data_len += new_len;
                hkey->data_ptr += new_len;
            }
        }
    }

    u32 new_len = 0;
    ret = FunctionList->SKF_EncryptFinal(hkey->skf_handle, hkey->data_ptr, &new_len);
    if (skf_error("SKF_EncryptFinal", ret)) {
        return ZZECODE_SKF_ERR;
    }
    hkey->data_len += new_len;
    hkey->data_ptr += new_len;

    *enc_len = hkey->data_len;
    *enc_data = malloc(hkey->data_len);
    memcpy(*enc_data, hkey->buf, hkey->data_len);

    free(hkey->buf);
    hkey->is_initialized = false;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_init(hkey_t *hkey, cparam_t param) {
    int ret;

    if (hkey->is_initialized) {
        return ZZECODE_CRYPT_ALREADY_INIT;
    }

    BLOCKCIPHERPARAM p = gen_block_cipher_param(&param);
    ret = FunctionList->SKF_DecryptInit(hkey->skf_handle, p);
    if (skf_error("SKF_DecryptInit", ret)) {
        return ZZECODE_SKF_ERR;
    }

    hkey->buf = malloc(VectorBufInitSize);
    hkey->buf_len = VectorBufInitSize;
    hkey->data_ptr = hkey->buf;
    hkey->data_len = 0;

    hkey->padding_type = param.padding_type;
    hkey->src_len = 0;
    hkey->block_size = 16; // due to limit of skf impl, only 16 is supported for none padding
    hkey->padding_buf = NULL;

    hkey->is_initialized = true;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_push(hkey_t *hkey, const u8 *data, size_t len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    // check upcomming length of data
    u32 new_len = 0;
    DISABLE {
        // NOTE: didn't fucking work (for impl of current skf library)
        //       use the code blow will break the crpyto process - for no reason.
        ret = FunctionList->SKF_DecryptUpdate(hkey->skf_handle, (u8 *)data, (u32)len, NULL, &new_len);
        if (skf_error("SKF_DecryptUpdate", ret)) {
            return ZZECODE_SKF_ERR;
        }
        if (new_len == 0) {
            new_len = (u32)len;
        }
    }
    else {
        // assume that the length of decrypted data is less than or equal to the length of encrypted data
        // that means new_len is not greater than len
        if (len > hkey->block_size) {
            new_len = (u32)len;
        } else {
            new_len = (u32)(hkey->block_size);
        }
    }

    // if buffer is not enough, realloc it
    size_t new_size = hkey->data_len + new_len;
    realloc_vector_buffer(hkey, new_size);

    // push data to buffer
    new_len = 0;
    ret = FunctionList->SKF_DecryptUpdate(hkey->skf_handle, (u8 *)data, (u32)len, hkey->data_ptr, &new_len);
    if (skf_error("SKF_DecryptUpdate", ret)) {
        return ZZECODE_SKF_ERR;
    }
    hkey->src_len += len;
    hkey->data_len += new_len;
    hkey->data_ptr += new_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_peek(const hkey_t *hkey, u8 **enc_data, size_t *enc_len) {
    if (!hkey->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    *enc_data = malloc(hkey->data_len);
    memcpy(*enc_data, hkey->buf, hkey->data_len);
    *enc_len = hkey->data_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_pop(hkey_t *hkey, u8 **enc_data, size_t *enc_len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPT_NO_INIT;
    }

    u32 new_len = 0;
    ret = FunctionList->SKF_DecryptFinal(hkey->skf_handle, hkey->data_ptr, &new_len);
    if (skf_error("SKF_DecryptFinal", ret)) {
        return ZZECODE_SKF_ERR;
    }
    hkey->data_len += new_len;
    hkey->data_ptr += new_len;

    u32 new_size;

    // remove padding data
    if (hkey->padding_type == zzcrypt_padding_zero) {
        new_size = unpadding_zero(hkey);
        if (new_size == 0) {
            return ZZECODE_PARAM_ERR;
        }

    } else if (hkey->padding_type == zzcrypt_padding_pkcs7) {
        new_size = unpadding_pkcs7(hkey);
        if (new_size == 0) {
            return ZZECODE_PARAM_ERR;
        }
    } else {
        new_size = hkey->data_len;
    }

    *enc_len = new_size;
    *enc_data = malloc(hkey->data_len);
    memcpy(*enc_data, hkey->buf, hkey->data_len);

    free(hkey->buf);
    hkey->buf = NULL;
    hkey->is_initialized = false;

    return ZZECODE_OK;
}

int zzcrypt_sm4_release(hkey_t *hkey) {
    if (hkey && !hkey->is_initialized) {
        return ZZECODE_DOUBLE_RELEASE;
    }
    if (hkey->buf) {
        free(hkey->buf);
    }
    if (hkey->padding_buf) {
        free(hkey->padding_buf);
    }
    free(hkey);

    return ZZECODE_OK;
}

int zzcrypt_file_list(const happ_t *happ, char **filenames) {
    u32 ret;
    if (!happ->is_initialized) {
        return ZZECODE_NO_INIT;
    }
    char *buf = malloc(1024);
    u32 buf_len = sizeof(buf);

    do {
        ret = FunctionList->SKF_EnumFiles(happ->skf_handle, buf, &buf_len);
        if (ret == SAR_BUFFER_TOO_SMALL) {
            buf_len *= 2;
            buf = realloc(buf, buf_len);
        } else if (ret == SAR_OK) {
            break;
        } else if (skf_error("SKF_EnumFiles", ret)) {
            free(buf);
            return ZZECODE_SKF_ERR;
        }
    } while (ret == SAR_BUFFER_TOO_SMALL);

    // replace '\0' with ','
    for (size_t i = 0; i < buf_len; i++) {
        if (buf[i] == '\0') {
            buf[i] = ',';
        }
    }

    buf = realloc(buf, buf_len - 1);
    buf[buf_len - 2] = '\0';
    *filenames = buf;

    return ZZECODE_OK;
}

int zzcrypt_file_write(const happ_t *happ, const char *filename, const u8 *data, size_t len) {
    u32 ret;
    if (!happ->is_initialized) {
        return ZZECODE_NO_INIT;
    }

    FILEATTRIBUTE info;
    ret = FunctionList->SKF_GetFileInfo(happ->skf_handle, (char *)filename, &info);
    if (ret == SAR_FILE_NOT_EXIST) {
    } else if (ret == SAR_OK) {
        return ZZECODE_FILE_ALREADY_EXIST;
    } else if (skf_error("GetFileInfo()", ret)) {
        return ZZECODE_SKF_ERR;
    }

    ret = FunctionList->SKF_CreateFile(happ->skf_handle, (char *)filename, len, SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
    if (skf_error("SKF_CreateFile()", ret)) {
        return ZZECODE_SKF_ERR;
    }

    ret = FunctionList->SKF_WriteFile(happ->skf_handle, (char *)filename, 0, (u8 *)data, len);
    if (skf_error("SKF_WriteFile()", ret)) {
        return ZZECODE_SKF_ERR;
    }

    return ZZECODE_OK;
}

int zzcrypt_file_read(const happ_t *happ, const char *filename, u8 **data, size_t *len) {
    u32 ret;
    if (!happ->is_initialized) {
        return ZZECODE_NO_INIT;
    }

    FILEATTRIBUTE info;
    ret = FunctionList->SKF_GetFileInfo(happ->skf_handle, (char *)filename, &info);
    if (ret == SAR_FILE_NOT_EXIST) {
        return ZZECODE_FILE_NOT_EXIST;
    } else if (skf_error("GetFileInfo()", ret)) {
        return ZZECODE_SKF_ERR;
    }

#ifdef ZZUTIL_DEBUG
    printf("file size: %d\n", info.FileSize);
#endif

    u32 buf_len = 1024;
    u8 *buf = malloc(buf_len);
    u32 empty_len = buf_len;
    u32 data_len = 0;
    u32 read_len = empty_len;
    while (data_len < info.FileSize) {
        ret = FunctionList->SKF_ReadFile(happ->skf_handle, (char *)filename, data_len, empty_len, buf + data_len, &read_len);
        if (skf_error("SKF_ReadFile", ret)) {
            free(buf);
            return ZZECODE_SKF_ERR;
        }
        if (read_len == 0 || read_len < empty_len) {
            data_len += read_len;
            break;
        } else {
            data_len += read_len;
            buf_len *= 2;
            buf = realloc(buf, buf_len);
            empty_len = buf_len - data_len;
            read_len = empty_len;
            continue;
        }
    };

    buf = realloc(buf, data_len);
    *data = buf;
    *len = data_len;

    return ZZECODE_OK;
}

int zzcrypt_file_remove(const happ_t *happ, const char *filename) {
    u32 ret;
    if (!happ->is_initialized) {
        return ZZECODE_NO_INIT;
    }

    FILEATTRIBUTE info;
    ret = FunctionList->SKF_GetFileInfo(happ->skf_handle, (char *)filename, &info);
    if (ret == SAR_FILE_NOT_EXIST) {
        return ZZECODE_FILE_NOT_EXIST;
    } else if (skf_error("GetFileInfo()", ret)) {
        return ZZECODE_SKF_ERR;
    }

    ret = FunctionList->SKF_DeleteFile(happ->skf_handle, (char *)filename);
    if (skf_error("SKF_DeleteFile", ret)) {
        return ZZECODE_SKF_ERR;
    }

    return ZZECODE_OK;
}

int zzcrypt_devinfo(const hdev_t *hdev, zzcrypt_devinfo_t *info) {
    u32 ret;
    if (!hdev->is_initialized) {
        return ZZECODE_NO_INIT;
    }

    DEVINFO inf;
    memset(&inf, 0, sizeof(DEVINFO));
    ret = FunctionList->SKF_GetDevInfo(hdev->skf_handle, &inf);
    if (skf_error("SKF_GetDevInfo", ret)) {
        return ZZECODE_SKF_ERR;
    }

    info->space_total = inf.TotalSpace;
    info->space_avali = inf.FreeSpace;
    memcpy(info->issuer, inf.Issuer, 64);
    memcpy(info->serial_number, inf.SerialNumber, 32);

    return ZZECODE_OK;
}

int zzcrypt_appinfo(const happ_t *happ, zzcrypt_appinfo_t *info) {
    u32 ret;

    strcpy(info->app_name, happ->app_name);
    info->retry = happ->retry;

    return ZZECODE_OK;
}

int zzcrypt_boot_from_dev(const hdev_t *hdev) {
    u32 ret;
    if (!hdev->is_initialized) {
        return ZZECODE_NO_INIT;
    }

#ifdef _WIN32
    // windows: check label: ukey_path[0] == exec_path[0]
    if (hdev->dev_name[0] == hdev->exec_path[0]) {
        return ZZECODE_OK;
    }
#endif

#ifdef _UNIX
    // linux: udevadm info /dev/sg0
    LOG("dev name: %s\n", hdev->dev_name);
    LOG("exec path: %s\n", hdev->exec_path);

    char dev_name[2048];
    strcpy(dev_name, "/dev/");
    strcpy(dev_name + 5, hdev->dev_name);
    LOG("dev name: %s\n", dev_name);

    struct stat statbuf;
    if (stat(hdev->exec_path, &statbuf) == -1) {
        return ZZECODE_CRYPT_WRONG_LOAD_POSITION;
    }
    char *exec_dev_name = get_device_from_mounts(statbuf.st_dev);
    LOG("exec dev name: %s\n", exec_dev_name);

    int exec_major, exec_minor;
    int dev_major, dev_minor;
    get_device_numbers(exec_dev_name, &exec_major, &exec_minor);
    get_device_numbers(dev_name, &dev_major, &dev_minor);
    LOG("exec %d:%d\ndev  %d:%d\n", exec_major, exec_minor, dev_major, dev_minor);

    if (exec_major == dev_major && exec_minor == dev_minor) {
        return ZZECODE_OK;
    }
#endif

    return ZZECODE_CRYPT_WRONG_LOAD_POSITION;
}

int zzcrypt_sm2_import_key_from_file(const hdev_t *hdev, const happ_t *happ, const char *filename, u8 **prikey_out) {
    int ret;
    u8 *prikey_pem = NULL;
    size_t prikey_len;

    // read pem file to openssl bio
    ret = zzcrypt_file_read(happ, filename, &prikey_pem, &prikey_len);
    if (ret != ZZECODE_OK) {
        return ret;
    }

    /* skip param pem if exists */ {
        const char *begin_str = "-----BEGIN SM2 PARAMETERS-----\n";
        const char *end_str = "-----END SM2 PARAMETERS-----\n";
        size_t begin_len = strlen(begin_str);
        u8 *begin_data = malloc(begin_len);
        memcpy(begin_data, begin_str, begin_len);
        size_t end_len = strlen(end_str);
        u8 *end_data = malloc(end_len);
        memcpy(end_data, end_str, end_len);

        u8 *begin_p = datdat(prikey_pem, prikey_len, begin_data, begin_len);
        u8 *end_p = datdat(prikey_pem, prikey_len, end_data, end_len);

        free(begin_data);
        free(end_data);

        if (begin_p != NULL && end_p != NULL) {
            size_t param_len = end_p + end_len - begin_p;
            prikey_len -= param_len;
            memmove(prikey_pem, end_p + end_len, prikey_len);
            prikey_pem = realloc(prikey_pem, prikey_len);
        }
    }

    u8 prikey[32];
    u8 pubkey[64];

    /* parse pem using opensll */ {
        int ok;

        BIO *mem = BIO_new_mem_buf(prikey_pem, prikey_len);
        if (mem == NULL) {
            free(prikey_pem);
            LOG("BIO_new_mem_buf failed\n");
            return ZZECODE_CRYPT_SSL_ERR;
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(mem, NULL, 0, NULL);
        if (pkey == NULL) {
            LOG("PEM_read_bio_PrivateKey failed\n");
            free(prikey_pem);
            BIO_free(mem);
            return ZZECODE_CRYPT_SSL_ERR;
        }

        free(prikey_pem);
        BIO_free(mem);

#ifdef ZZUTIL_DEBUG
        const OSSL_PARAM *params = EVP_PKEY_gettable_params(pkey);
        if (!params) {
            LOG("EVP_PKEY_gettable_params failed\n");
            EVP_PKEY_free(pkey);
            return ZZECODE_CRYPT_SSL_ERR;
        }
        // for (size_t i = 0; params[i].key != 0; ++i) {
        //     printf("%s: %d\n", params[i].key, params[i].data_type);
        // }
#endif

        /* get private key */ {
            BIGNUM *bn = NULL;
            ok = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn);
            if (!ok) {
                LOG("EVP_PKEY_get_bn_param failed\n");
                EVP_PKEY_free(pkey);
                return ZZECODE_CRYPT_SSL_ERR;
            }
            size_t len = BN_num_bytes(bn);
            u8 *buf = malloc(len);
            len = BN_bn2bin(bn, buf);
            if (len == 0) {
                LOG("BN_bn2bin failed\n");
                EVP_PKEY_free(pkey);
                free(buf);
                return ZZECODE_CRYPT_SSL_ERR;
            }
            if (len == 32) {
                memcpy(prikey, buf, 32);
                free(buf);
            } else {
                EVP_PKEY_free(pkey);
                free(buf);
                return ZZECODE_CRYPT_BAD_FORMAT;
            }
        }

        /* get public key */ {
            size_t len;
            ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len);
            if (!ok) {
                LOG("EVP_PKEY_get_octet_string_param failed\n");
                EVP_PKEY_free(pkey);
                return ZZECODE_CRYPT_SSL_ERR;
            }
            u8 *buf = malloc(len);
            ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, buf, len, &len);
            if (!ok) {
                LOG("EVP_PKEY_get_octet_string_param failed\n");
                EVP_PKEY_free(pkey);
                free(buf);
                return ZZECODE_CRYPT_SSL_ERR;
            }
            // remove leading 0x04
            if (len == 64) {
                memcpy(pubkey, buf, 64);
                free(buf);
            } else if (len == 65 && buf[0] == 0x04) {
                memcpy(pubkey, buf + 1, 64);
                free(buf);
            } else {
                EVP_PKEY_free(pkey);
                free(buf);
                return ZZECODE_CRYPT_BAD_FORMAT;
            }
        }

        EVP_PKEY_free(pkey);
    }

    ret = zzcrypt_sm2_import_key(hdev, happ, prikey, pubkey);
    if (ret != ZZECODE_OK) {
        return ret;
    }

    *prikey_out = malloc(32);
    memcpy(*prikey_out, prikey, 32);
    return ZZECODE_OK;
}

int zzcrypt_sm2_get_pubkey_from_file(const hdev_t *hdev, const happ_t *happ, const char *filename, u8 **pubkey_out) {
    int ret;
    u8 *crt_pem = NULL;
    size_t crt_len;

    ret = zzcrypt_file_read(happ, filename, &crt_pem, &crt_len);
    if (ret != ZZECODE_OK) {
        return ret;
    }

    u8 pubkey[64];
    /* parse pem using opensll */ {
        int ok;

        BIO *mem = BIO_new_mem_buf(crt_pem, crt_len);
        if (mem == NULL) {
            free(crt_pem);
            LOG("BIO_new_mem_buf failed\n");
            return ZZECODE_CRYPT_SSL_ERR;
        }

        X509 *x509 = PEM_read_bio_X509(mem, NULL, 0, NULL);
        if (x509 == NULL) {
            LOG("PEM_read_bio_X509 failed\n");
            free(crt_pem);
            BIO_free(mem);
            return ZZECODE_CRYPT_SSL_ERR;
        }

        free(crt_pem);
        BIO_free(mem);

        EVP_PKEY *pkey = X509_get_pubkey(x509);
        if (pkey == NULL) {
            LOG("X509_get_pubkey failed\n");
            X509_free(x509);
            return ZZECODE_CRYPT_SSL_ERR;
        }

        X509_free(x509);

#ifdef ZZUTIL_DEBUG
        const OSSL_PARAM *params = EVP_PKEY_gettable_params(pkey);

        // for (size_t i = 0; params[i].key != 0; ++i) {
        //     printf("%s: %d\n", params[i].key, params[i].data_type);
        // }
#endif

        /* get public key */ {
            size_t len;
            ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len);
            if (!ok) {
                LOG("EVP_PKEY_get_octet_string_param failed\n");
                EVP_PKEY_free(pkey);
                return ZZECODE_CRYPT_SSL_ERR;
            }
            u8 *buf = malloc(len);
            ok = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, buf, len, &len);
            if (!ok) {
                LOG("EVP_PKEY_get_octet_string_param failed\n");
                EVP_PKEY_free(pkey);
                free(buf);
                return ZZECODE_CRYPT_SSL_ERR;
            }

            // remove leading 0x04
            if (len == 64) {
                memcpy(pubkey, buf, 64);
                free(buf);
            } else if (len == 65 && buf[0] == 0x04) {
                memcpy(pubkey, buf + 1, 64);
                free(buf);
            } else {
                EVP_PKEY_free(pkey);
                free(buf);
                return ZZECODE_CRYPT_BAD_FORMAT;
            }
        }

        EVP_PKEY_free(pkey);
    }

    *pubkey_out = malloc(64);
    memcpy(*pubkey_out, pubkey, 64);

    return ZZECODE_OK;
}

int zzcrypt_dev_exists(const hdev_t *hdev) {
    u32 ret;
    if (!hdev->is_initialized) {
        return ZZECODE_NO_INIT;
    }
    u32 pulDevState;
    ret = FunctionList->SKF_GetDevState((char *)(hdev->dev_name), &pulDevState);
    if (skf_error("SKF_GetDevState", ret)) {
        return ZZECODE_SKF_ERR;
    }
    if (pulDevState != 1) {
        return ZZECODE_CRYPT_NO_DEVICE;
    };
    return ZZECODE_OK;
}

/************************************************************
 * Internal functions
 ************************************************************/

bool load_library(const char *exec_path) {
    int ret = 0;
    void *lib_handle = NULL;
    char path[1024] = {0};
    strcpy(path, exec_path);

    P_SKF_GetFuncList get_func_list = NULL;
#ifdef _WIN32
    strcat_s(path, sizeof(path), "\\skf.dll");
    lib_handle = LoadLibrary(path);
    if (lib_handle == NULL) {
        ret = GetLastError();
        if (log_output) {
            LOG("LoadLibrary error: %d\n", ret);
        }
        return false;
    }
    get_func_list = (P_SKF_GetFuncList)GetProcAddress(lib_handle, "SKF_GetFuncList");
    if (get_func_list == NULL) {
        ret = GetLastError();
        LOG("GetProcAddress error: %d", ret);
        return false;
    }
#elif _UNIX
    strcat(path, "/libskf.so");
    lib_handle = dlopen(path, RTLD_LAZY);
    if (!lib_handle) {
        LOG("dlopen error: %s.\n", dlerror());
        return false;
    }

    get_func_list = dlsym(lib_handle, "SKF_GetFuncList");
    if (get_func_list == NULL) {
        LOG("dlsym error: %s.\n", dlerror());
        return false;
    }
#endif

    ret = get_func_list(&FunctionList);
    if (ret) {
        return false;
    }

    return true;
}

size_t sm2_sizeof_encoded_data(size_t cipher_len) {
    return sizeof(ECCCIPHERBLOB) + cipher_len - 1; // - sizeof(u8 *);
}

void print_device_info(skf_handle_t hdev) {
    int ret = 0;
    DEVINFO info;
    char devices[256];
    char exec_path[256];
    u32 devices_size;

    memset(&info, 0, sizeof(info));
    ret = FunctionList->SKF_GetDevInfo(hdev, &info);
    if (ret) {
        LOG("SKF_GetDevInfo() failed: %#x\n", ret);
        return;
    }

    int device_count;
    {
        int idx = 0;
        char *p = devices;
        size_t pos = 0;
        while (pos < devices_size) {
            LOG("device[%d]: %s\n", idx++, p);
            pos += strlen(p) + 1;
        }
        device_count = idx;
    }

    LOG("SerialNumber: %s\n", info.SerialNumber);
    LOG("DevAuthAlgId: 0x%x\n", info.DevAuthAlgId);
    LOG("TotalSpace: %d\n", info.TotalSpace);
    LOG("FreeSpace: %d\n", info.FreeSpace);
}

bool skf_error(const char *msg, int ret) {
    if (ret == 0) {
        return false;
    } else {
        if (log_output) {
            LOG("%s failed: 0x%08x\n", msg, ret);
        }
        return true;
    }
}

BLOCKCIPHERPARAM gen_block_cipher_param(const cparam_t *param) {
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(BLOCKCIPHERPARAM));

    if (param->iv_len > 0) {
        memcpy(p.IV, param->iv, param->iv_len);
        p.IVLen = (u32)param->iv_len;
    } else {
        p.IVLen = 0;
    }

    switch (param->padding_type) {
    case zzcrypt_padding_pkcs5:
        // use padding implementation of skf library
        p.PaddingType = PKCS5_PADDING;
        break;
    case zzcrypt_padding_zero:
        // use padding implementation of our own
        p.PaddingType = NO_PADDING;
        break;
    case zzcrypt_padding_pkcs7:
        // use padding implementation of our own
        p.PaddingType = NO_PADDING;
        break;
    case zzcrypt_padding_none:
    default:
        p.PaddingType = NO_PADDING;
        break;
    }

    return p;
}

void realloc_vector_buffer(hkey_t *hkey, size_t new_size) {
    while (new_size > hkey->buf_len) {
        hkey->buf_len *= 2;
        hkey->buf = realloc(hkey->buf, hkey->buf_len);
        hkey->data_ptr = hkey->buf + hkey->data_len;
    }
}

u8 rand_none_zero_byte() {
    u8 b;
    do {
        b = rand() & 0xff;
    } while (b == 0);
    return b;
}

size_t padding_zero(hkey_t *hkey) {
    u32 block_size = hkey->block_size;
    u32 len = hkey->src_len;
    u32 remain = block_size - (len % block_size);
    if (remain != 0) {
        hkey->padding_buf = malloc(remain);
        memset(hkey->padding_buf, 0, remain);
    }
    return remain;
}

size_t padding_pkcs7(hkey_t *hkey) {
    u32 block_size = hkey->block_size;
    u32 len = hkey->src_len + 1; // last byte must be padding size
    u32 remain = block_size - (len % block_size);
    hkey->padding_buf = malloc(remain + 1);
    if (remain != 0) {
        for (u32 i = 0; i < remain - 1; i++) {
            hkey->padding_buf[i] = rand_none_zero_byte();
        }
    }
    hkey->padding_buf[remain] = remain + 1;
    return remain + 1;
}

size_t unpadding_zero(hkey_t *hkey) {
    u32 block_size = hkey->block_size;
    if (hkey->data_len % block_size != 0) {
        return 0;
    }
    // get last block
    u8 *p = hkey->buf + hkey->data_len - 1;
    u32 remain = 0;
    while (remain < block_size && *p == 0x00) {
        remain += 1;
        p -= 1;
    }
    return hkey->data_len - remain;
}

size_t unpadding_pkcs7(hkey_t *hkey) {
    u32 block_size = hkey->block_size;
    if (hkey->data_len % block_size != 0) {
        LOG("unpadding_pkcs7: data_len is not multiple of block_size\n");
        return 0;
    }
    // get last byte
    u8 *p = hkey->buf + hkey->data_len - 1;
    u32 remain = *p;
    if (remain > block_size) {
        LOG("unpadding_pkcs7: padding size is greater than block_size\n");
        return 0;
    }
    // check padding
    return hkey->data_len - remain;
}

u8 *datdat(const u8 *dat1, size_t len1, const u8 *dat2, size_t len2) {
    for (size_t i = 0; i <= len1 - len2; ++i) {
        if (memcmp(dat1 + i, dat2, len2) == 0) {
            return (u8 *)(dat1 + i);
        }
    }
    return NULL;
}

bool get_exec_path(char *buf, size_t len) {
#ifdef _WIN32
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    u8 *p = strrchr(path, '\\');
    if (p) {
        *p = 0;
    }
#elif _UNIX
    char path[512];
    getcwd(path, sizeof(path));
#endif
    if (strlen(path) < len) {
        strcpy(buf, path);
        return true;
    } else {
        return false;
    }
}

#ifdef _UNIX

#define MOUNT_FILE "/proc/mounts"

// 获取挂载点对应的设备路径
char *get_device_from_mounts(dev_t dev) {
    FILE *fp = fopen(MOUNT_FILE, "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    static char device[256], mountpoint[256], fstype[256], options[256];
    int dump, pass;
    while (fscanf(fp, "%255s %255s %255s %255s %d %d\n",
                  device, mountpoint, fstype, options, &dump, &pass) != EOF) {
        struct stat statbuf;
        if (stat(mountpoint, &statbuf) == 0 && statbuf.st_dev == dev) {
            fclose(fp);
            return strdup(device);
        }
    }

    fclose(fp);
    return NULL;
}

#define SYSFS_PATH "/sys/class/scsi_generic/%s/device/%s"

// 读取 sysfs 文件内容
void read_sysfs_file(const char *device, const char *filename, char *result) {
    char path[256];
    snprintf(path, sizeof(path), SYSFS_PATH, device, filename);

    FILE *file = fopen(path, "r");
    if (file) {
        char buffer[64];
        if (fgets(buffer, sizeof(buffer), file)) {
            strcpy(result, buffer);
        }
        fclose(file);
    } else {
        perror("fopen");
    }
}

#include <sys/sysmacros.h>

// 获取设备的 major 和 minor 号
int get_device_numbers(const char *dev, int *major, int *minor) {
    struct stat statbuf;
    if (stat(dev, &statbuf) == -1) {
        perror("stat");
        return -1;
    }
    *major = major(statbuf.st_rdev);
    *minor = minor(statbuf.st_rdev);
    return 0;
}

#endif
