#ifndef MG_BLOCKCIPHER_H
#define MG_BLOCKCIPHER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "mg_aes.h"
#include "mg_aria.h"
#include "mg_lea.h"
#include "mg_crypto.h"
#include "mg_common.h"

typedef struct {
    uint8_t iv[MG_CRYPTO_MAX_IV_SIZE]; // maximum size of IV
    uint32_t iv_len;                   // IV len (byte)
    uint32_t modeID;                   // 무슨 운영모드
    uint32_t paddingID;                // 무슨 패딩
} mg_cipher_param;

typedef union {
    mg_aria_key aria; // aria rk
    mg_lea_key lea;   // lea rk
    mg_aes_key aes;   // aes rk
} key_ctx_t;

typedef struct {
    mg_cipher_param param; // param 구조체 (IV, mode, padding)
    uint32_t alg_ID;       // 무슨 알고리즘 사용하는지 (LEA,ARIA,HIGHT)
    uint32_t dir;          // MG_Crypto_ENCRYPT/DECRYPT
    uint32_t block_len;    // 알고리즘의 블록 크기(len) (byte수)
    key_ctx_t key_ctx;     // 알고리즘에 맞는 키 구조체
    uint8_t key[32];       // master key, byte는 최대 키 길이로 설정
    uint32_t key_len;      // 실제 key len (byte)
    uint8_t buf[16];       // 남은 byte 저장, maximum size of block
    uint32_t buf_len;      // 실제 남은 데이터가 들어있는 len (byte)
} mg_cipher_ctx;

int32_t MG_Crypto_BlockCipher_Encrypt(mg_cipher_ctx* ctx,
                                      const uint8_t* in,
                                      uint8_t* out);

int32_t MG_Crypto_BlockCipher_Decrypt(mg_cipher_ctx* ctx,
                                      const uint8_t* in,
                                      uint8_t* out);

int32_t MG_Crypto_BlockCipher_Mode(mg_cipher_ctx* ctx,
                                   const uint8_t* in,
                                   const uint32_t in_len,
                                   uint8_t* out,
                                   uint32_t* out_len);

int32_t MG_Crypto_BlockCipher_ECB(mg_cipher_ctx* ctx,
                                  const uint8_t* in,
                                  const uint32_t in_len,
                                  uint8_t* out,
                                  uint32_t* out_len);

int32_t MG_Crypto_BlockCipher_Padding(uint8_t* buf,
                                      const uint32_t buf_len,
                                      const uint32_t block_len,
                                      const uint32_t paddingID);

int32_t MG_Crypto_EncryptInit(mg_cipher_ctx* ctx,
                              const uint8_t* key,
                              const uint32_t key_len,
                              const uint32_t alg_ID,
                              const uint32_t dir,
                              const mg_cipher_param* param);

int32_t MG_Crypto_EncryptUpdate(mg_cipher_ctx* ctx,
                                const uint8_t* in,
                                const uint32_t in_len,
                                uint8_t* out,
                                uint32_t* out_len);

int32_t MG_Crypto_EncryptFinal(mg_cipher_ctx* ctx,
                               uint8_t* out,
                               uint32_t* out_len);

int32_t MG_Crypto_Encrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint32_t in_len,
                          uint8_t* out,
                          uint32_t* out_len);

int32_t MG_Crypto_DecryptInit(mg_cipher_ctx* ctx,
                              const uint8_t* key,
                              const uint32_t key_len,
                              const uint32_t alg_ID,
                              const uint32_t dir,
                              const mg_cipher_param* param);

int32_t MG_Crypto_DecryptUpdate(mg_cipher_ctx* ctx,
                                const uint8_t* in,
                                const uint32_t in_len,
                                uint8_t* out,
                                uint32_t* out_len);

int32_t MG_Crypto_DecryptFinal(mg_cipher_ctx* ctx,
                               uint8_t* out,
                               uint32_t* out_len);

int32_t MG_Crypto_Decrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint32_t in_len,
                          uint8_t* out,
                          uint32_t* out_len);

#endif // MG_BLOCKCIPHER_H