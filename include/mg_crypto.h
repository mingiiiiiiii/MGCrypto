#ifndef MG_CRYPTO_H
#define MG_CRYPTO_H

#include <stdint.h>

#define MG_SUCCESS 0
#define MG_FAIL -1
#define MG_NOT_INIT -2

// Cipher Mode
#define MG_CRYPTO_DIR_ENCRYPT 0
#define MG_CRYPTO_DIR_DECRYPT 1

#define MG_CRYPTO_MODE_ECB 0
#define MG_CRYPTO_MODE_CBC 1
#define MG_CRYPTO_MODE_CTR 2
#define MG_CRYPTO_MODE_GCM 3

// Block Cipher
#define MG_CRYPTO_ID_ARIA 0
#define MG_CRYPTO_ID_LEA 1
#define MG_CRYPTO_ID_HIGHT 2
#define MG_CRYPTO_ID_AES 3

// Hash Algorithm
#define MG_HASH_ID_SHA2_256 4
#define MG_HASH_ID_SHA2_384 5
#define MG_HASH_ID_SHA2_512 6
#define MG_HASH_ID_SHA3_224 7
#define MG_HASH_ID_SHA3_256 8
#define MG_HASH_ID_SHA3_384 9
#define MG_HASH_ID_SHA3_512 10
#define MG_HASH_ID_SHAKE128 11
#define MG_HASH_ID_SHAKE256 12
#define MG_HASH_ID_LSH512 13
#define MG_HMAC_ID_HMAC_SHA2_256 14
#define MG_HMAC_ID_HMAC_SHA2_384 15
#define MG_HMAC_ID_HMAC_SHA2_512 16

#define MG_CRYPTO_MAX_IV_SIZE 16

#define MG_CRYPTO_PADDING_NO 0      // 패딩 없음
#define MG_CRYPTO_PADDING_ZERO 1    // 패딩 0으로
#define MG_CRYPTO_PADDING_ONEZERO 2 // 패딩 최상단 1 이후 0
#define MG_CRYPTO_PADDING_PKCS 3    // 패딩 필요한 블록 수 만큼, 3 블록 필요한 경우 03 03 03 03 패딩, 패딩이 필요없는 경우 패딩 방법을 표시하기 위해 10 10 10 10 10... 추가

// Error codes
typedef enum {
    MG_GCM_SUCCESS = 0,
    MG_GCM_ERROR_INVALID_KEY_LEN = -1,
    MG_GCM_ERROR_CONTEXT_INIT = -2,
    MG_GCM_ERROR_IV_LEN = -3,
    MG_GCM_ERROR_AAD = -4,
    MG_GCM_ERROR_ENCRYPT_FAILED = -5,
    MG_GCM_ERROR_DECRYPT_FAILED = -6,
    MG_GCM_ERROR_TAG_MISMATCH = -7,
    MG_GCM_ERROR_FILE_IO = -8,
    MG_GCM_ERROR_BUFFER_ALLOC = -9,
    MG_GCM_ERROR_INVALID_PARAM = -10,
    MG_GCM_ERROR_TAG_LEN = -11
} mg_gcm_error_t;

#endif // MG_CRYPTO_H