#ifndef MG_GCM_H
#define MG_GCM_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mg_aes.h"
#include "mg_crypto.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
    #define DECLARE_IS_ENDIAN const int ossl_is_little_endian = __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define IS_LITTLE_ENDIAN (ossl_is_little_endian)
    #define IS_BIG_ENDIAN (!ossl_is_little_endian)
    #if defined(L_ENDIAN) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
        #error "L_ENDIAN defined on a big endian machine"
    #endif
    #if defined(B_ENDIAN) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        #error "B_ENDIAN defined on a little endian machine"
    #endif
    #if !defined(L_ENDIAN) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        #define L_ENDIAN
    #endif
    #if !defined(B_ENDIAN) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
        #define B_ENDIAN
    #endif
#else
    #define DECLARE_IS_ENDIAN \
        const union {         \
            long one;         \
            char little;      \
        } ossl_is_endian = {1}

    #define IS_LITTLE_ENDIAN (ossl_is_endian.little != 0)
    #define IS_BIG_ENDIAN (ossl_is_endian.little == 0)
#endif

typedef void (*block128_f)(const unsigned char in[16],
                           unsigned char out[16],
                           const void* key);

#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
    #define STRICT_ALIGNMENT 0
#endif

#if defined(__GNUC__) && !STRICT_ALIGNMENT
typedef size_t size_t_aX __attribute((__aligned__(1)));
#else
typedef size_t size_t_aX;
#endif

// #undef GETU32
// #if defined(BSWAP4) && !defined(STRICT_ALIGNMENT)
//     #define GETU32(p) BSWAP4(*(const uint32_t*)(p))
//     #define PUTU32(p, v) *(uint32_t*)(p) = BSWAP4(v)
// #else
//     #define GETU32(p) ((uint32_t)(p)[0] << 24 | (uint32_t)(p)[1] << 16 | (uint32_t)(p)[2] << 8 | (uint32_t)(p)[3])
//     #define PUTU32(p, v) ((p)[0] = (uint8_t)((v) >> 24), (p)[1] = (uint8_t)((v) >> 16), (p)[2] = (uint8_t)((v) >> 8), (p)[3] = (uint8_t)(v))
// #endif

typedef struct
{
    uint64_t hi, lo;
} u128;

typedef void (*gcm_init_fn)(u128 Htable[16],
                            const uint64_t H[2]);
typedef void (*gcm_ghash_fn)(uint64_t Xi[2],
                             const u128 Htable[16],
                             const uint8_t* inp,
                             size_t len);
typedef void (*gcm_gmult_fn)(uint64_t Xi[2],
                             const u128 Htable[16]);
struct gcm_funcs_st {
    gcm_init_fn ginit;
    gcm_ghash_fn ghash;
    gcm_gmult_fn gmult;
};

struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union {
        uint64_t u[2];
        uint32_t d[4];
        uint8_t c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Yi, EKi, EK0, len, Xi, H and pre-computed Htable is
     * used in some assembler modules, i.e. don't change the order!
     */
    u128 Htable[16];
    struct gcm_funcs_st funcs;
    unsigned int mres, ares;
    block128_f block;
    void* key;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    unsigned char Xn[48];
#endif
};

typedef struct gcm128_context GCM128_CONTEXT;

// GCM
// Stack based
void CRYPTO_gcm128_init(GCM128_CONTEXT* ctx,
                        void* key,
                        block128_f block);

void CRYPTO_gcm128_setiv(GCM128_CONTEXT* ctx,
                         const unsigned char* iv,
                         size_t len);

int CRYPTO_gcm128_aad(GCM128_CONTEXT* ctx,
                      const unsigned char* aad,
                      size_t len);

int CRYPTO_gcm128_encrypt(GCM128_CONTEXT* ctx,
                          const unsigned char* in,
                          unsigned char* out,
                          size_t len);

int CRYPTO_gcm128_decrypt(GCM128_CONTEXT* ctx,
                          const unsigned char* in,
                          unsigned char* out,
                          size_t len);

int CRYPTO_gcm128_finish(GCM128_CONTEXT* ctx,
                         const unsigned char* tag,
                         size_t len);

void CRYPTO_gcm128_tag(GCM128_CONTEXT* ctx,
                       unsigned char* tag,
                       size_t len);

// Heap based
GCM128_CONTEXT* CRYPTO_gcm128_new(void* key,
                                  block128_f block);
void CRYPTO_gcm128_release(GCM128_CONTEXT* ctx);

// Context structure for combined AES-GCM operations
typedef struct {
    GCM128_CONTEXT* gcm_ctx;
    mg_aes_key aes_key;
    unsigned char iv[16];  // GCM IV (Nonce)
    unsigned char tag[16]; // GCM Authentication Tag
    size_t tag_len;        // Length of the authentication tag (typically 16 bytes)
    int is_encrypt;        // 1 for encrypt, 0 for decrypt
} mg_aes_gcm_ctx_t;

// Buffer size for streaming. Adjust based on performance tuning.
#define STREAM_BUFFER_SIZE (4 * 1024) // 4KB buffer

/**
 * @brief AES-GCM 암호화 작업을 초기화합니다.
 *
 * @param key 암호화에 사용할 AES 키 (16, 24 또는 32 바이트)
 * @param key_len 키의 길이 (16, 24, 32)
 * @param iv GCM IV (Nonce). 12바이트를 권장하며, 각 암호화 세션마다 고유해야 합니다.
 * @param iv_len IV의 길이
 * @param aad 추가 인증 데이터 (선택 사항). NULL인 경우 사용되지 않습니다.
 * @param aad_len AAD의 길이. aad가 NULL이 아닌 경우 0보다 커야 합니다.
 * @param output_tag 암호화 후 생성될 GCM 인증 태그를 저장할 버퍼 (최소 16바이트).
 * 이 태그는 복호화 시 사용됩니다.
 * @param output_tag_len output_tag 버퍼의 크기. 최소 16바이트를 권장합니다.
 * @param input_file 암호화할 원본 파일의 파일 포인터
 * @param output_file 암호화된 데이터를 쓸 파일의 파일 포인터
 * @return 성공 시 MG_GCM_SUCCESS(0), 실패 시 음수 오류 코드
 */
int mg_gcm_encrypt_file(const unsigned char* key,
                        size_t key_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        unsigned char* output_tag,
                        size_t output_tag_len,
                        FILE* input_file,
                        FILE* output_file);

/**
 * @brief AES-GCM 복호화 작업을 초기화합니다.
 *
 * @param key 복호화에 사용할 AES 키 (16, 24 또는 32 바이트)
 * @param key_len 키의 길이 (16, 24, 32)
 * @param iv GCM IV (Nonce). 암호화에 사용된 IV와 동일해야 합니다.
 * @param iv_len IV의 길이
 * @param aad 추가 인증 데이터 (선택 사항). 암호화 시 사용된 AAD와 동일해야 합니다.
 * NULL인 경우 사용되지 않습니다.
 * @param aad_len AAD의 길이. aad가 NULL이 아닌 경우 0보다 커야 합니다.
 * @param input_tag GCM 인증 태그. 암호화 시 생성된 태그와 동일해야 합니다.
 * @param input_tag_len input_tag 버퍼의 크기. 암호화 시 사용된 태그 길이와 동일해야 합니다.
 * @param input_file 복호화할 암호화된 파일의 파일 포인터
 * @param output_file 복호화된 데이터를 쓸 파일의 파일 포인터
 * @return 성공 시 MG_GCM_SUCCESS(0), 실패 시 음수 오류 코드 (태그 불일치 포함)
 */
int mg_gcm_decrypt_file(const unsigned char* key,
                        size_t key_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        const unsigned char* input_tag,
                        size_t input_tag_len,
                        FILE* input_file,
                        FILE* output_file);

#endif // MG_GCM_H