/// @file zzcrypt.h
/// @brief Header file for cryptographic utilities in the zzutil library.

#ifndef ZZUTIL_ZZCRYPT_H
#define ZZUTIL_ZZCRYPT_H

#include <stdio.h>
#include <stdint.h>

struct _zzcrypt_devhandle;
struct _zzcrypt_keyhandle;
struct _zzcrypt_apphandle;
typedef struct _zzcrypt_devhandle zzcrypt_devhandle_t, *zzcrypt_devhandle_p;
typedef struct _zzcrypt_keyhandle zzcrypt_keyhandle_t, *zzcrypt_keyhandle_p;
typedef struct _zzcrypt_apphandle zzcrypt_apphandle_t, *zzcrypt_apphandle_p;

/// @brief 加密时的对齐方式
typedef enum _zzcrypt_padding_t {
    /// @brief 无填充
    zzcrypt_padding_none = 0,
    /// @brief 0 填充
    zzcrypt_padding_zero = 1,
    /// @brief PKCS5 填充
    zzcrypt_padding_pkcs5 = 5,
    /// @brief PKCS7 填充
    zzcrypt_padding_pkcs7 = 7,
} zzcrypt_padding_t;

/// @brief 加密算法
typedef enum _zzcrypt_algorithm_t {
    /// @brief SM4 ECB 模式
    zzcrypt_algorithm_sm4ecb = 1,
    /// @brief SM4 CBC 模式
    zzcrypt_algorithm_sm4cbc = 2,
    /// @brief SM4 CFB 模式
    zzcrypt_algorithm_sm4cfb = 3,
    /// @brief SM4 OFB 模式
    zzcrypt_algorithm_sm4ofb = 4,
} zzcrypt_algorithm_t;

/// @brief 加密参数
typedef struct _zzcrypt_cipherp_param {
    /// @brief 加密算法
    zzcrypt_algorithm_t algorithm;
    /// @brief 初始向量
    uint8_t *iv;
    /// @brief 初始向量长度
    size_t iv_len;
    /// @brief 对齐方式
    zzcrypt_padding_t padding_type;
} zzcrypt_cipherp_param_t;

typedef struct _zzcrypt_devinfo {
    char issuer[64];
    char serial_number[32];
    unsigned space_total;
    unsigned space_avali;
} zzcrypt_devinfo_t;

typedef struct _zzcrypt_appinfo {
    char app_name[128];
    unsigned retry;
} zzcrypt_appinfo_t;

/// @brief 初始化设备，生成一个加密设备句柄
/// @param[out] hdev 设备句柄
/// @param[in] log 日志文件句柄
/// @return 错误代码, 0 表示成功
int zzcrypt_init(zzcrypt_devhandle_t **hdev, FILE *log);

/// @brief 初始化应用，生成一个应用句柄
/// @param[in] hdev 设备句柄
/// @param[in] app_name 应用名称
/// @param[in] pin PIN 码
/// @param[out] happ 应用句柄
/// @return 错误代码, 0 表示成功
int zzcrypt_init_app(const zzcrypt_devhandle_t *hdev, const char *app_name, const char *pin, zzcrypt_apphandle_t **happ);

/// @brief 释放应用句柄
/// @param[in] happ
/// @return 错误代码, 0 表示成功
int zzcrypt_release_app(zzcrypt_apphandle_t *happ);

/// @brief 导入 SM2 密钥对
/// @param[in] hdev 设备句柄
/// @param[in] happ 应用句柄
/// @param[in] prikey 私钥串(二进制表示)
/// @param[in] pubkey 公钥串(二进制表示)
/// @return 错误代码, 0 表示成功
int zzcrypt_sm2_import_key(const zzcrypt_devhandle_t *hdev, const zzcrypt_apphandle_t *happ, const uint8_t *prikey, const uint8_t *pubkey);

/// @brief 从 PEM 文件中加载 SM2 密钥对
/// @param[in] happ 应用句柄
/// @param[in] filename PEM 文件名
/// @return 错误代码, 0 表示成功
int zzcrypt_sm2_import_key_from_file(const zzcrypt_devhandle_t *hdev, const zzcrypt_apphandle_t *happ, const char *filename, uint8_t **prikey);

/// @brief 从文件中获取公钥
/// @param[in] hdev 设备句柄
/// @param[in] happ 应用句柄
/// @param[in] filename CRT 文件名
/// @param[in] pubkey 公钥串(二进制表示)
/// @return 错误代码, 0 表示成功
int zzcrypt_sm2_get_pubkey_from_file(const zzcrypt_devhandle_t *hdev, const zzcrypt_apphandle_t *happ, const char *filename, uint8_t **pubkey);

/// @brief SM2 加密, 需要首先导入 SM2 密钥对
/// @param[in] hdev 设备句柄
/// @param[in] pubkey 公钥串(二进制表示)
/// @param[in] data 待加密数据
/// @param[in] len 待加密数据长度
/// @param[out] enc_data 加密数据
/// @param[out] enc_len 加密数据长度
/// @return 错误代码, 0 表示成功
int zzcrypt_sm2_encrypt(const zzcrypt_devhandle_t *hdev, const uint8_t *pubkey, const uint8_t *data, size_t len, uint8_t **enc_data, size_t *enc_len);

/// @brief SM2 解密, 需要首先导入 SM2 密钥对
/// @param[in] hdev 设备句柄
/// @param[in] prikey 私钥串(二进制表示)
/// @param[in] enc_data 待解密数据
/// @param[in] enc_len 待解密数据长度
/// @param[out] data 解密数据
/// @param[out] len 解密数据长度
/// @return 错误代码, 0 表示成功
int zzcrypt_sm2_decrypt(const zzcrypt_devhandle_t *hdev, const uint8_t *prikey, const uint8_t *enc_data, size_t enc_len, uint8_t **data, size_t *len);

/// @brief 导入密钥
/// @param[in] hdev 设备句柄
/// @param[in] key sm4 密钥串(二进制表示)
/// @param[out] hkey 加密句柄
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_import_key(const zzcrypt_devhandle_t *hdev, const uint8_t *key, zzcrypt_keyhandle_t **hkey);

/// @brief 初始化 SM4 加密, 初始化后可以调用任意次数的 push, peek 操作
/// @param[in] hkey 加密句柄
/// @param[in] param 加密参数
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_encrypt_init(zzcrypt_keyhandle_t *hkey, zzcrypt_cipherp_param_t param);

/// @brief 向缓存中追加加密数据
/// @param[in] hkey 加密句柄
/// @param[in] data 待加密数据
/// @param[in] len 待加密数据长度
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_encrypt_push(zzcrypt_keyhandle_t *hkey, const uint8_t *data, size_t len);

/// @brief 检查缓存中最新加密完成的数据
/// @param[in] hkey 加密句柄
/// @param[out] enc_data 加密数据
/// @param[out] enc_len 加密数据长度
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_encrypt_peek(const zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

/// @brief 弹出加密完成的数据, 并释放资源, 不再允许 push, peek 操作
/// @param[in] hkey 加密句柄
/// @param[out] enc_data 加密数据
/// @param[out] enc_len 加密数据长度
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_encrypt_pop(zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

/// @brief 初始化 SM4 解密, 初始化后可以调用任意次数的 push, peek 操作
/// @param[in] hkey 解密句柄
/// @param[in] param 解密参数
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_decrypt_init(zzcrypt_keyhandle_t *hkey, zzcrypt_cipherp_param_t param);

/// @brief 向缓存中追加解密数据
/// @param[in] hkey 解密句柄
/// @param[in] data 待解密数据
/// @param[in] len 待解密数据长度
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_decrypt_push(zzcrypt_keyhandle_t *hkey, const uint8_t *data, size_t len);

/// @brief 检查缓存中最新解密完成的数据
/// @param[in] hkey 解密句柄
/// @param[out] enc_data 解密数据
/// @param[out] enc_len 解密数据长度
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_decrypt_peek(const zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

/// @brief 弹出解密完成的数据, 并释放资源, 不再允许 push, peek 操作
/// @param[in] hkey 解密句柄
/// @param[out] enc_data 解密数据
/// @param[out] enc_len 解密数据长度
int zzcrypt_sm4_decrypt_pop(zzcrypt_keyhandle_t *hkey, uint8_t **enc_data, size_t *enc_len);

/// @brief 释放加密句柄, hkey 所指向资源将被为无效，需要重新初始化
/// @param[in] hkey 加密句柄
/// @return 错误代码, 0 表示成功
int zzcrypt_sm4_release(zzcrypt_keyhandle_t *hkey);

/// @brief 枚举文件
/// @param[in] happ 应用句柄
/// @param[out] filenames, split by comma
/// @param[out] len
int zzcrypt_file_list(const zzcrypt_apphandle_t *happ, char **filenames);

/// @brief 写入文件
/// @param[in] happ 应用句柄
/// @param[in] filename
/// @param[in] data
/// @param[in] len
/// @return 错误代码, 0 表示成功
int zzcrypt_file_write(const zzcrypt_apphandle_t *happ, const char *filename, const uint8_t *data, size_t len);

/// @brief 读取文件
/// @param[in] happ 应用句柄
/// @param[in] filename
/// @param[out] data
/// @param[out] len
/// @return 错误代码, 0 表示成功
int zzcrypt_file_read(const zzcrypt_apphandle_t *happ, const char *filename, uint8_t **data, size_t *len);

/// @brief 删除文件
/// @param[in] happ
/// @param[in] filename
/// @return 错误代码, 0 表示成功
int zzcrypt_file_remove(const zzcrypt_apphandle_t *happ, const char *filename);

int zzcrypt_devinfo(const zzcrypt_devhandle_t *hdev, zzcrypt_devinfo_t *info);

int zzcrypt_appinfo(const zzcrypt_apphandle_t *happ, zzcrypt_appinfo_t *info);

int zzcrypt_boot_from_dev(const zzcrypt_devhandle_t *hdev);

#endif // ZZUTIL_ZZCRYPT_H
