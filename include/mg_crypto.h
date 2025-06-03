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

#define MG_CRYPTO_MAX_IV_SIZE 16

#define MG_CRYPTO_PADDING_NO 0      // 패딩 없음
#define MG_CRYPTO_PADDING_ZERO 1    // 패딩 0으로
#define MG_CRYPTO_PADDING_ONEZERO 2 // 패딩 최상단 1 이후 0
#define MG_CRYPTO_PADDING_PKCS 3    // 패딩 필요한 블록 수 만큼, 3 블록 필요한 경우 03 03 03 03 패딩, 패딩이 필요없는 경우 패딩 방법을 표시하기 위해 10 10 10 10 10... 추가

#endif // MG_CRYPTO_H