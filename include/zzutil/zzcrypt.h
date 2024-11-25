/// @file zzcrypt.h
/// @brief Header file for cryptographic utilities in the zzutil library.

#ifndef ZZUTIL_ZZCRYPT_H
#define ZZUTIL_ZZCRYPT_H

#include <stdio.h>
#include <stdint.h>

struct _zzcrypt_devhandle;
struct _zzcrypt_keyhandle;
typedef struct _zzcrypt_devhandle zzcrypt_devhandle_t, *zzcrypt_devhandle_p;
typedef struct _zzcrypt_keyhandle zzcrypt_keyhandle_t, *zzcrypt_keyhandle_p;

/// @brief 加密时的对齐方式
typedef enum _zzcrypt_padding_t {
    /// @brief 无填充
    zzcrypt_padding_none = 0,
    /// @brief 0 填充
    zzcrypt_padding_zero = 1,
    /// @brief PKCS5 填充
    zzcrypt_padding_pkcs5 = 5,
    /// @brief PKCS7 填充 (未实现)
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

/// @brief 初始化设备，生成一个加密设备句柄
/// @param[out] hdev 设备句柄
/// @param[in] log 日志文件句柄
/// @return 错误代码, 0 表示成功
int zzcrypt_init(zzcrypt_devhandle_t **hdev, FILE *log);

int zzcrypt_sm2_encrypt(const zzcrypt_devhandle_t *hdev, const uint8_t *pubkey, const uint8_t *data, size_t len, uint8_t **enc_data, size_t *enc_len);

int zzcrypt_sm2_import_key(const zzcrypt_devhandle_t *hdev, const uint8_t *prikey, const uint8_t *pubkey, zzcrypt_keyhandle_t **hkey);

int zzcrypt_sm2_decrypt(const zzcrypt_devhandle_t *hdev, const uint8_t *prikey, const uint8_t *enc_data, size_t enc_len, uint8_t **data, size_t *len);

int zzcrypt_sm2_sign(const zzcrypt_devhandle_t *hdev, const uint8_t *prikey, const uint8_t *data, size_t len, uint8_t **sign, size_t *sign_len);

int zzcrypt_sm2_verify(const zzcrypt_devhandle_t *hdev, const uint8_t *pubkey, const uint8_t *data, size_t len, const uint8_t *sign, size_t sign_len);

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

#endif // ZZUTIL_ZZCRYPT_H
