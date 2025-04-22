#ifndef MG_ARIA_H
#define MG_ARIA_H

#include <stdint.h>
#include <mg_blockcipher.h>

void DL(const unsigned char* i,
        unsigned char* o);

void RotXOR(const unsigned char* s,
            int n,
            unsigned char* t);

typedef struct {
    uint32_t rk[272]; // 16 * (R + 1), MAX of R = 16
    // uint32_t key_len; // 16, 24, 32 bytes
    uint32_t round; // 12, 14, 16
} mg_aria_key;

int EncKeySetup(const unsigned char* w0,
                mg_aria_key* aria_key,
                int keyBits);

int DecKeySetup(const unsigned char* w0,
                mg_aria_key* aria_key,
                int keyBits);

int32_t Crypt(const unsigned char* p,
              int R,
              const unsigned char* e,
              unsigned char* c);

int32_t MG_Crypto_ARIA_KeySetup(mg_aria_key* aria_key,
                                const uint8_t* userKey,
                                const uint32_t bits,
                                const int32_t dir);

int32_t MG_Crypto_ARIA_Encrypt(uint8_t* out,
                               const uint8_t* in,
                               mg_aria_key* aria_key);

int32_t MG_Crypto_ARIA_Decrypt(uint8_t* out,
                               const uint8_t* in,
                               mg_aria_key* aria_key);

void printBlockOfLength(unsigned char* b,
                        int len);

void printBlock(unsigned char* b);

#endif // MG_ARIA_H