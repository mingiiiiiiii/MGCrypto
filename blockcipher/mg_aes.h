
#ifndef MG_AES_H
#define MG_AES_H

#include <stdint.h>
#include "mg_crypto.h"

#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] << 8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st)                    \
    {                                     \
        (ct)[0] = (uint32_t)((st) >> 24); \
        (ct)[1] = (uint32_t)((st) >> 16); \
        (ct)[2] = (uint32_t)((st) >> 8);  \
        (ct)[3] = (uint32_t)(st);         \
    }

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