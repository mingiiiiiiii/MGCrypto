#ifndef MG_BLOCKCIPHER_H
#define MG_BLOCKCIPHER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <mg_aes.h>
#include <mg_aria.h>
#include <mg_lea.h>
#include <mg_crypto.h>

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
    uint32_t algID;        // 무슨 알고리즘 사용하는지 (LEA,ARIA,HIGHT)
    uint32_t dir;          // MG_Crypto_ENCRYPT/DECRYPT
    uint32_t block_size;   // 알고리즘의 블록 크기(byte수)
    key_ctx_t key_ctx;     // 알고리즘에 맞는 키 구조체
    uint8_t key[32];       // master key, byte는 최대 키 길이로 설정
    uint32_t key_len;      // 실제 key len (byte)
    uint8_t buf[16];       // 남은 byte 저장, maximum size of block
    uint32_t buf_len;      // 실제 remain len (byte)
} mg_cipher_ctx;

#endif // MG_BLOCKCIPHER_H