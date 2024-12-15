#include "zzutil/zzcrypt.h"
#include "common/helper.h"

#include <zzutil/zzcrypt.h>
#include <zzutil/errmsg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _UNIX
#include <unistd.h>
#include <dlfcn.h>
#endif

#include <skf.h>

/************************************************************
 * Declears
 ************************************************************/

typedef struct _zzcrypt_devhandle hdev_t;
typedef struct _zzcrypt_keyhandle hkey_t;
typedef struct _zzcrypt_apphandle app_t;
typedef struct _zzcrypt_ctnhandle ctn_t;
typedef struct _zzcrypt_cipherp_param cparam_t;
typedef HANDLE skf_handle_t;

static PSKF_FUNCLIST FunctionList;
static bool is_initialized = false;
static const u32 DeviceLockTimeout = 5000;
static FILE *log_output = NULL;
static const size_t VectorBufInitSize = 256;

static bool load_library();
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

/************************************************************
 * Public functions
 ************************************************************/

struct _zzcrypt_devhandle {
    skf_handle_t skf_handle;
    bool is_initialized;
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
};

struct _zzcrypt_ctnhandle {
    HCONTAINER skf_handle;
    bool is_initialized;
};

int zzcrypt_init(hdev_t **hdev, FILE *log) {
    int ret;
    u8 devices[128] = {0};
    u8 app_name_buf[128];
    u32 devices_size = sizeof(devices);

    hdev_t *h = malloc(sizeof(hdev_t));
    h->is_initialized = false;
    *hdev = h;

    log_output = log;

    if (is_initialized) {
        return ZZECODE_CRYPO_ALREADY_INIT;
    }

    if (!load_library() && log_output) {
        fprintf(log_output, "Load library failed\n");
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

    /* connect device */
    ret = FunctionList->SKF_ConnectDev(devices, &h->skf_handle);
    if (skf_error("SKF_ConnectDev", ret)) {
        return ZZECODE_SKF_ERR;
    }

    /* get ukey DevAuthAlgId */ DISABLE {
        print_device_info((*hdev)->skf_handle);
    }

    /* enmu all app */
    int len = sizeof(app_name_buf);
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

int zzcrypt_init_app(const hdev_t *hdev, const char *app_name, const char *pin, app_t **happ) {
    int ret;

    if (!hdev->is_initialized) {
        return ZZECODE_NO_INIT;
    }

    app_t *app = malloc(sizeof(zzcrypt_apphandle_t));
    *happ = app;
    app->is_initialized = false;
    ret = FunctionList->SKF_OpenApplication(hdev->skf_handle, (char *)app_name, &app->skf_handle);
    if (skf_error("SKF_OpenApplication", ret)) {
        return ZZECODE_SKF_ERR;
    }

    ret = FunctionList->SKF_VerifyPIN(app->skf_handle, USER_TYPE, (char *)pin, &app->retry);
    if (skf_error("SKF_VerifyPIN", ret)) {
        return ZZECODE_SKF_ERR;
    }

    return ZZECODE_OK;
}

int zzcrypt_sm2_import_key(const hdev_t *hdev, const app_t *happ, const uint8_t *prikey, const uint8_t *pubkey) {

    /**
     *how to import sm2 keypair:
     *1\prepare sm2 keypair into buf
     *2\prepare the struct PENVELOPEDKEYBLOB :env
     *3\get the pubkey form ukey, copy pubkey to env
     *4\use sm1 algo encrypt prikey and then copy to env.cbEncryptedPriKey
     *5\use sm2 pubkey encrypt sm1 key ,and then copy to env.ECCCipherBlob
     *6\call SKF_ImportECCKeyPair
     */

    int ret;

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
    int ctn_type = 0;
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

int zzcrypt_sm2_encrypt(const hdev_t *hdev, const uint8_t *pubkey, const uint8_t *data, size_t len, uint8_t **enc_data, size_t *enc_len) {
    int ret;
    if (!hdev->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
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

int zzcrypt_sm2_decrypt(const hdev_t *hdev, const uint8_t *prikey, const uint8_t *enc_data, size_t enc_len, uint8_t **data, size_t *len) {
    int ret;

    if (!hdev->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
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

int zzcrypt_sm4_import_key(const hdev_t *hdev, const uint8_t *key, hkey_t **hkey) {
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
        return ZZECODE_CRYPO_ALREADY_INIT;
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

int zzcrypt_sm4_encrypt_push(hkey_t *hkey, const uint8_t *data, size_t len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
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

int zzcrypt_sm4_encrypt_peek(const hkey_t *hkey, uint8_t **enc_data, size_t *enc_len) {
    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
    }

    *enc_data = malloc(hkey->data_len);
    memcpy(*enc_data, hkey->buf, hkey->data_len);
    *enc_len = hkey->data_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_pop(hkey_t *hkey, uint8_t **enc_data, size_t *enc_len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
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
        return ZZECODE_CRYPO_ALREADY_INIT;
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

int zzcrypt_sm4_decrypt_push(hkey_t *hkey, const uint8_t *data, size_t len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
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

int zzcrypt_sm4_decrypt_peek(const hkey_t *hkey, uint8_t **enc_data, size_t *enc_len) {
    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
    }

    *enc_data = malloc(hkey->data_len);
    memcpy(*enc_data, hkey->buf, hkey->data_len);
    *enc_len = hkey->data_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_pop(hkey_t *hkey, uint8_t **enc_data, size_t *enc_len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
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

int zzcrypt_sm4_release(zzcrypt_keyhandle_t *hkey) {
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

/************************************************************
 * Internal functions
 ************************************************************/

bool load_library() {
    int ret = 0;
    void *lib_handle = NULL;
    char path[128] = {0};

#ifdef _WIN32
    P_SKF_GetFuncList GetFunction = NULL;
    GetModuleFileName(NULL, path, MAX_PATH);
    uint8_t *p = strrchr(path, '\\');
    if (p) {
        *p = 0;
    }
#ifdef _WIN64
    strcat_s(path, sizeof(path), "\\SKF_ukey_x86_64_1.7.22.0117.dll");
#else
    strcat_s(path, sizeof(path), "\\SKF_ukey_i686_1.7.22.0117.dll");
#endif
    lib_handle = LoadLibrary(path);
    if (lib_handle == NULL) {
        ret = GetLastError();
        if (log_output) {
            fprintf(log_output, "Failed to load dll %s (error %d)\n", path, ret);
        }
        return false;
    }
    GetFunction = (P_SKF_GetFuncList)GetProcAddress(lib_handle, "SKF_GetFuncList");
    if (GetFunction == NULL) {
        ret = GetLastError();
        return false;
    }
    ret = GetFunction(&FunctionList);
    if (ret) {
        return false;
    }
#else
    P_SKF_GetFuncList get_func_list;

    getcwd(path, sizeof(path));
    strcat(path, "/libskf.so");
    lib_handle = dlopen(path, RTLD_LAZY);
    if (!lib_handle) {
        fprintf(log_output, "Open Error:%s.\n", dlerror());
        return false;
    }

    get_func_list = dlsym(lib_handle, "SKF_GetFuncList");
    if (get_func_list == NULL) {
        fprintf(log_output, "Dlsym Error:%s.\n", dlerror());
        return false;
    }

    ret = get_func_list(&FunctionList);
    if (ret) {
        fprintf(log_output, "fnGetList ERROR 0x%x", ret);
        return false;
    }
#endif

    return true;
}

size_t sm2_sizeof_encoded_data(size_t cipher_len) {
    return sizeof(ECCCIPHERBLOB) + cipher_len - 1; // - sizeof(u8 *);
}

void print_device_info(skf_handle_t hdev) {
    int ret = 0;
    DEVINFO info;

    memset(&info, 0, sizeof(info));
    ret = FunctionList->SKF_GetDevInfo(hdev, &info);
    if (ret) {
        fprintf(log_output, "SKF_GetDevInfo() failed: %#x\n", ret);
        return;
    }

    fprintf(log_output, "SerialNumber: %s\n", info.SerialNumber);
    fprintf(log_output, "DevAuthAlgId: 0x%x\n", info.DevAuthAlgId);
    fprintf(log_output, "TotalSpace: %d\n", info.TotalSpace);
    fprintf(log_output, "FreeSpace: %d\n", info.FreeSpace);
}

bool skf_error(const char *msg, int ret) {
    if (ret == 0) {
        return false;
    } else {
        if (log_output) {
            fprintf(log_output, "%s failed: 0x%08x\n", msg, ret);
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
        // TODO - use padding implementation of our own
        p.PaddingType = NO_PADDING;
        break;
    case zzcrypt_padding_pkcs7:
        // TODO - use padding implementation of our own
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
    if (remain != 0) {
        hkey->padding_buf = malloc(remain);
        for (u32 i = 0; i < remain - 1; i++) {
            hkey->padding_buf[i] = rand_none_zero_byte();
        }
        hkey->padding_buf[remain - 1] = remain;
    }
    return remain;
}

size_t unpadding_zero(hkey_t *hkey) {
    u32 block_size = hkey->block_size;
    if (hkey->data_len % block_size != 0) {
        return 0;
    }
    // get last block
    u8 *p = hkey->buf + hkey->data_len - 1;
    u32 remain = 0;
    while (remain < block_size && *p == 0) {
        remain += 1;
        p -= 1;
    }
    return hkey->data_len - remain;
}
size_t unpadding_pkcs7(hkey_t *hkey) {
    u32 block_size = hkey->block_size;
    if (hkey->data_len % block_size != 0) {
        return 0;
    }
    // get last byte
    u8 *p = hkey->buf + hkey->data_len - 1;
    u32 remain = *p;
    if (remain > block_size) {
        return 0;
    }
    // check padding
    return hkey->data_len - remain;
}
