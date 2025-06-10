#include <stdint.h>

// "mg_blockcipher.h"
typedef struct {
    uint8_t iv[16];     // maximum size of IV
    uint32_t iv_len;    // IV len (byte)
    uint32_t modeID;    // 무슨 운영모드
    uint32_t paddingID; // 무슨 패딩
} mg_cipher_param;

int32_t MG_Crypto_Decrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint64_t in_len,
                          uint8_t* out,
                          uint32_t* out_len);

int32_t MG_Crypto_Encrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint64_t in_len,
                          uint8_t* out,
                          uint32_t* out_len);

// "mg_hash.h"
int32_t MG_Crypto_Hash(const uint8_t* in,
                       const uint64_t in_len,
                       uint8_t* out,
                       const uint32_t out_len,
                       const uint32_t hash_id);

// "mg_hmac.h"
int32_t MG_Crypto_HMAC(const uint8_t* key,
                       const uint32_t keylen,
                       const uint8_t* msg,
                       const uint32_t msglen,
                       uint8_t* hmac,
                       const uint32_t hmac_id);