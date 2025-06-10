
#ifndef MG_AES_H
#define MG_AES_H

#include <stdint.h>
#include "mg_crypto.h"

#undef GETU32
#if defined(BSWAP4) && !defined(STRICT_ALIGNMENT)
    #define GETU32(p) BSWAP4(*(const uint32_t*)(p))
    #define PUTU32(p, v) *(uint32_t*)(p) = BSWAP4(v)
#else
    #define GETU32(p) ((uint32_t)(p)[0] << 24 | (uint32_t)(p)[1] << 16 | (uint32_t)(p)[2] << 8 | (uint32_t)(p)[3])
    #define PUTU32(p, v) ((p)[0] = (uint8_t)((v) >> 24), (p)[1] = (uint8_t)((v) >> 16), (p)[2] = (uint8_t)((v) >> 8), (p)[3] = (uint8_t)(v))
#endif

typedef struct {
    uint32_t rk[60]; // AES round keys
    int round;       // number of rounds
} mg_aes_key;

int AES_set_encrypt_key(const unsigned char* userKey,
                        const int bits,
                        mg_aes_key* aes_key);

int AES_set_decrypt_key(const unsigned char* userKey,
                        const int bits,
                        mg_aes_key* aes_key);

int32_t AES_encrypt(const unsigned char* in,
                    unsigned char* out,
                    const mg_aes_key* aes_key);

int32_t AES_decrypt(const unsigned char* in,
                    unsigned char* out,
                    const mg_aes_key* aes_key);

int32_t MG_Crypto_AES_KeySetup(mg_aes_key* aes_key,
                               const uint8_t* userKey,
                               const int bits,
                               const int dir);

int32_t MG_Crypto_AES_Encrypt(uint8_t* out,
                              const uint8_t* in,
                              const mg_aes_key* aes_key);

int32_t MG_Crypto_AES_Decrypt(uint8_t* out,
                              const uint8_t* in,
                              const mg_aes_key* aes_key);

#endif // MG_AES_H