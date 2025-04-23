#ifndef MG_LEA_H
#define MG_LEA_H

#include <stdint.h>
#include <mg_blockcipher.h>

#define ROR(W, i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W, i) (((W) << (i)) | ((W) >> (32 - (i))))

#define ctow(w, c) (*(w) = *((unsigned int*)(c)))
#define wtoc(c, w) (*((unsigned int*)(c)) = *(w))
#define loadU32(v) (v)
typedef struct {
    uint32_t rk[192]; // 최대 32개의 192-bit 라운드키
    // uint32_t key_len; // 16, 24, 32 bytes
    uint32_t round; // 24, 28, 32
} mg_lea_key;

int32_t MG_Crypto_LEA_KeySetup(mg_lea_key* key,
                               const uint8_t* mk,
                               uint32_t mk_len);

int32_t lea_encrypt(unsigned char* ct,
                 const unsigned char* pt,
                 const mg_lea_key* key);

int32_t lea_decrypt(unsigned char* pt,
                 const unsigned char* ct,
                 const mg_lea_key* key);

int32_t MG_Crypto_LEA_Encrypt(uint8_t* ct,
                              const uint8_t* pt,
                              const mg_lea_key* lea_key);

int32_t MG_Crypto_LEA_Decrypt(uint8_t* pt,
                              const uint8_t* ct,
                              const mg_lea_key* lea_key);

#endif // MG_LEA_H