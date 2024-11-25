#include <stdio.h>
#include <stdbool.h>

#include <zzutil/zzcrypt.h>
#include <zzutil/zzhex.h>
#include <zzutil/errmsg.h>

#include <skf.h>

#include "common/helper.h"

/************************************************************
 * Declears
 ************************************************************/

typedef struct _zzcrypt_devhandle dev_t;
typedef struct _zzcrypt_keyhandle key_t;
typedef struct _zzcrypt_cipherp_param cparam_t;
typedef HANDLE skf_handle_t;

static PSKF_FUNCLIST FunctionList;
static bool is_initialized = false;
static const u32 DEVICE_LOCK_TIMEOUT = 5000;
static FILE *log_output = NULL;

static bool load_library();
static size_t sizeof_encoded_data(size_t cipher_len);
static void print_device_info(skf_handle_t hdev);
static bool skf_error(const char *msg, int ret);
static BLOCKCIPHERPARAM gen_block_cipher_param(const cparam_t *param);
static bool read_key_from_hex_string(const char *str, u8 **key, size_t *key_len);

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
    u32 buf_len;
    u8 *data_ptr;
    u32 data_len;
};

int zzcrypt_init(dev_t **hdev, FILE *log) {
    int ret;
    u8 devices[128] = {0};
    u8 app_name_buf[128];
    u32 devices_size = sizeof(devices);

    log_output = log;

    if (is_initialized) {
        return ZZECODE_DEV_ALREADY_INIT;
    }

    if (!load_library() && log_output) {
        fprintf(log_output, "Load library failed\n");
        return ZZECODE_OS_ERROR;
    }

    /* get device name */
    ret = FunctionList->SKF_EnumDev(1, devices, &devices_size);
    if (skf_error("SKF_EnumDev", ret)) {
        return ZZECODE_SKF_ERR;
    }

    *hdev = malloc(sizeof(dev_t));
    (*hdev)->is_initialized = false;

    /* connect device */
    ret = FunctionList->SKF_ConnectDev(devices, &((*hdev)->skf_handle));
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
        ret = FunctionList->SKF_LockDev((*hdev)->skf_handle, DEVICE_LOCK_TIMEOUT);
        if (skf_error("SKF_LockDev", ret)) {
            return ZZECODE_SKF_ERR;
        }
    }

    (*hdev)->is_initialized = true;
    is_initialized = true;

    return ZZECODE_OK;
}

int zzcrypt_sm2_encrypt(const dev_t *hdev, const uint8_t *pubkey, const uint8_t *data, size_t len, uint8_t **enc_data, size_t *enc_len) {
    int ret;

    PECCPUBLICKEYBLOB p_pubkey = malloc(sizeof(ECCPUBLICKEYBLOB));
    memset(p_pubkey, 0, sizeof(ECCPUBLICKEYBLOB));
    p_pubkey->BitLen = 256;
    memcpy(p_pubkey->XCoordinate + 32, pubkey, 32);
    memcpy(p_pubkey->YCoordinate + 32, pubkey + 32, 32);

    PECCCIPHERBLOB p_res = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB));
    ret = FunctionList->SKF_ExtECCEncrypt(hdev->skf_handle, p_pubkey, (u8 *)data, (u32)len, p_res);
    if (skf_error("SKF_ExtECCEncrypt", ret)) {
        return ZZECODE_SKF_ERR;
    }

    size_t real_len = sizeof_encoded_data((size_t)(p_res->CipherLen));
    *enc_len = real_len;
    *enc_data = malloc(real_len * sizeof(u8));
    memcpy(*enc_data, p_res, real_len * sizeof(u8));

    return ZZECODE_OK;
}

int zzcrypt_sm2_decrypt(const dev_t *hdev, const uint8_t *prikey, const uint8_t *enc_data, size_t enc_len, uint8_t **data, size_t *len) {
    int ret;

    PECCPRIVATEKEYBLOB p_prikey = malloc(sizeof(ECCPRIVATEKEYBLOB));
    memset(p_prikey, 0, sizeof(ECCPRIVATEKEYBLOB));
    p_prikey->BitLen = 256;
    memcpy(p_prikey->PrivateKey + 32, prikey, 32);

    PECCCIPHERBLOB p_enc_data = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB) + enc_len * sizeof(u8) - sizeof(u8 *));
    p_enc_data->CipherLen = (u32)enc_len;
    memcpy(p_enc_data, enc_data, enc_len * sizeof(u8));

    u8 *buf = malloc(enc_len * sizeof(u8)); // typically, the decrypted data is not longer than the encrypted data
    u32 de_len = (u32)enc_len;
    ret = FunctionList->SKF_ExtECCDecrypt(hdev->skf_handle, p_prikey, p_enc_data, buf, &de_len);
    if (skf_error("SKF_ExtECCDecrypt", ret)) {
        return ZZECODE_SKF_ERR;
    }

    *len = de_len;
    *data = malloc(de_len * sizeof(u8));
    memcpy(*data, buf, de_len * sizeof(u8));

    return ZZECODE_OK;
}

int zzcrypt_sm4_import_key(const dev_t *hdev, const uint8_t *key, key_t **hkey) {
    int ret;

    *hkey = malloc(sizeof(key_t));
    (*hkey)->is_initialized = false;
    ret = FunctionList->SKF_SetSymmKey(hdev->skf_handle, (u8 *)key, SGD_SMS4_ECB, &((*hkey)->skf_handle));
    if (skf_error("SKF_SetSymmKey", ret)) {
        return ZZECODE_SKF_ERR;
    }

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_init(key_t *hkey, cparam_t param) {
    int ret;

    if (hkey->is_initialized) {
        return ZZECODE_OK;
    }

    BLOCKCIPHERPARAM p = gen_block_cipher_param(&param);
    ret = FunctionList->SKF_EncryptInit(hkey->skf_handle, p);
    if (skf_error("SKF_EncryptInit", ret)) {
        return ZZECODE_SKF_ERR;
    }

    hkey->buf = malloc(1024 * sizeof(u8));
    hkey->buf_len = 1024;
    hkey->data_ptr = hkey->buf;
    hkey->data_len = 0;

    hkey->is_initialized = true;

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_push(key_t *hkey, const uint8_t *data, size_t len) {
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
        new_len = (u32)len * 2;
    }

    // if buffer is not enough, realloc it
    while (hkey->data_len + new_len > hkey->buf_len) {
        hkey->buf_len *= 2;
        hkey->buf = realloc(hkey->buf, hkey->buf_len);
    }

    // TODO: padding data if needed

    // push data to buffer
    // u32 left = hkey->buf_len - hkey->data_len;
    new_len = 0;
    ret = FunctionList->SKF_EncryptUpdate(hkey->skf_handle, (u8 *)data, (u32)len, hkey->data_ptr, &new_len);
    if (skf_error("SKF_EncryptUpdate", ret)) {
        return ZZECODE_SKF_ERR;
    }
    hkey->data_len += new_len;
    hkey->data_ptr += new_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_peek(const key_t *hkey, uint8_t **enc_data, size_t *enc_len) {
    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
    }

    *enc_data = hkey->buf;
    *enc_len = hkey->data_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_encrypt_pop(key_t *hkey, uint8_t **enc_data, size_t *enc_len) {
    int ret;

    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
    }

    u32 new_len = 0;
    ret = FunctionList->SKF_EncryptFinal(hkey->skf_handle, hkey->data_ptr, &new_len);
    if (skf_error("SKF_EncryptFinal", ret)) {
        return ZZECODE_SKF_ERR;
    }
    hkey->data_len += new_len;
    hkey->data_ptr += new_len;

    *enc_len = hkey->data_len;
    *enc_data = malloc(hkey->data_len * sizeof(u8));
    memcpy(*enc_data, hkey->buf, hkey->data_len * sizeof(u8));

    free(hkey->buf);
    hkey->is_initialized = false;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_init(key_t *hkey, cparam_t param) {
    int ret;

    if (hkey->is_initialized) {
        return ZZECODE_OK;
    }

    BLOCKCIPHERPARAM p = gen_block_cipher_param(&param);
    ret = FunctionList->SKF_DecryptInit(hkey->skf_handle, p);
    if (skf_error("SKF_DecryptInit", ret)) {
        return ZZECODE_SKF_ERR;
    }

    hkey->buf = malloc(1024 * sizeof(u8));
    hkey->buf_len = 1024;
    hkey->data_ptr = hkey->buf;
    hkey->data_len = 0;

    hkey->is_initialized = true;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_push(key_t *hkey, const uint8_t *data, size_t len) {
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
        new_len = (u32)len;
    }

    // if buffer is not enough, realloc it
    while (hkey->data_len + new_len > hkey->buf_len) {
        hkey->buf_len *= 2;
        hkey->buf = realloc(hkey->buf, hkey->buf_len);
    }

    // TODO: padding data if needed

    // push data to buffer
    new_len = 0;
    ret = FunctionList->SKF_DecryptUpdate(hkey->skf_handle, (u8 *)data, (u32)len, hkey->data_ptr, &new_len);
    if (skf_error("SKF_DecryptUpdate", ret)) {
        return ZZECODE_SKF_ERR;
    }
    hkey->data_len += new_len;
    hkey->data_ptr += new_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_peek(const key_t *hkey, uint8_t **enc_data, size_t *enc_len) {
    if (!hkey->is_initialized) {
        return ZZECODE_CRYPO_NO_INIT;
    }

    *enc_data = hkey->buf;
    *enc_len = hkey->data_len;

    return ZZECODE_OK;
}

int zzcrypt_sm4_decrypt_pop(key_t *hkey, uint8_t **enc_data, size_t *enc_len) {
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

    *enc_len = hkey->data_len;
    *enc_data = malloc(hkey->data_len * sizeof(u8));
    memcpy(*enc_data, hkey->buf, hkey->data_len * sizeof(u8));

    free(hkey->buf);
    hkey->is_initialized = false;

    return ZZECODE_OK;
}

/************************************************************
 * Internal functions
 ************************************************************/

bool load_library() {
    int ret = 0;
    void *lib_handle = NULL;
    uint8_t path[128] = {0};

#ifdef _WIN32
    P_SKF_GetFuncList GetFunction = NULL;
    GetModuleFileName(NULL, path, MAX_PATH);
    uint8_t *p = strrchr(path, '\\');
    if (p) {
        *p = 0;
    }
    strcat_s(path, sizeof(path), "\\SKF_ukey_x86_64_1.7.22.0117.dll");
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

size_t sizeof_encoded_data(size_t cipher_len) {
    return sizeof(ECCCIPHERBLOB) - 1 + cipher_len;
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
        memcpy(p.IV, param->iv, param->iv_len * sizeof(u8));
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
        // use padding implementation of skf library
        p.PaddingType = ZERO_PADDING;
        break;
    case zzcrypt_padding_pkcs7:
        // use padding implementation of our own
        p.PaddingType = 0;
        break;
    case zzcrypt_padding_none:
    default:
        p.PaddingType = 0;
        break;
    }

    return p;
}

bool read_key_from_hex_string(const char *str, u8 **key, size_t *key_len) {
    zzhex_hex_to_bin(str, key, key_len);
}
