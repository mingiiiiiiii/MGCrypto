#include "mg_blockcipher.h"

// init -> update -> final
// init: 키 설정, mode 설정?
/*
    상대가 뭘 입력하지?
    어떤 암호 알고리즘(+어떤 보안강도) 쓸건지, 운용모드는 뭐 쓸건지,
    평문, 키, IV, (+패딩?)

    -> 평문, 평문 길이, 암호키, 암호키 길이, 암호알고리즘 식별, IV, IV 길이, 운용모드, 패딩

*/

int32_t MG_Crypto_EncryptInit();
int32_t MG_Crypto_EncryptUpdate();
int32_t MG_Crypto_EncryptFinal();
int32_t MG_Crypto_Encrypt();

int32_t MG_Crypto_DecryptInit();
int32_t MG_Crypto_DecryptUpdate();
int32_t MG_Crypto_DecryptFinal();
int32_t MG_Crypto_Decrypt();

int32_t MG_Crypto_BlockCipher_Encrypt(mg_cipher_ctx* ctx,
                                      const uint8_t* in,
                                      uint8_t* out) {
    int32_t ret = 0;
    switch(ctx->algID) {
    case MG_CRYPTO_ID_ARIA:
        ret = MG_Crypto_ARIA_Encrypt(out, in, &ctx->key_ctx.aria);
        break;
    case MG_CRYPTO_ID_LEA:
        ret = MG_Crypto_LEA_Encrypt(out, in, &ctx->key_ctx.lea);
        break;
    case MG_CRYPTO_ID_AES:
        ret = MG_Crypto_AES_Encrypt(out, in, &ctx->key_ctx.aes);
        break;
    default:
        ret = MG_FAIL; // todo: change error code
        break;
    }
    return ret;
}

int32_t MG_Crypto_BlockCipher_Decrypt(mg_cipher_ctx* ctx,
                                      const uint8_t* in,
                                      uint8_t* out) {
    int32_t ret = 0;
    switch(ctx->algID) {
    case MG_CRYPTO_ID_ARIA:
        ret = MG_Crypto_ARIA_Decrypt(out, in, &ctx->key_ctx.aria);
        break;
    case MG_CRYPTO_ID_LEA:
        ret = MG_Crypto_LEA_Decrypt(out, in, &ctx->key_ctx.lea);
        break;
    case MG_CRYPTO_ID_AES:
        ret = MG_Crypto_AES_Decrypt(out, in, &ctx->key_ctx.aes);
        break;
    default:
        ret = MG_FAIL; // todo: change error code
        break;
    }
    return ret;
}

// int32_t MG_Crypto_Core(mg_cipher_ctx* ctx,
//                        const uint8_t* in,
//                        uint8_t* out,
//                        int dir) {
//     int32_t ret = 0;
//     switch(ctx->algID) {
//     case MG_CRYPTO_ID_ARIA:
//         ret = MG_ARIA_Core(out, in, &ctx->key_ctx.aria, dir);
//         break;
//     case MG_CRYPTO_ID_LEA:
//         ret = MG_LEA_Core(out, in, &ctx->key_ctx.lea, dir);
//         break;
//     case MG_CRYPTO_ID_AES:
//         ret = MG_AES_Core(out, in, &ctx->key_ctx.aes, dir);
//         break;
//     default:
//         ret = MG_FAIL; // todo: change error code
//         break;
//     }
//     return ret;
// }

int32_t MG_Crypto_BlockCipher_ECB(mg_cipher_ctx* ctx,
                                  const uint8_t* in,
                                  const uint32_t in_len,
                                  uint8_t* out,
                                  uint32_t* out_len) {
    int32_t ret = 0;

    uint32_t i = 0;
    uint32_t block_size = ctx->block_size;

    if(ctx == NULL || in == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    switch(ctx->dir) {
    case MG_CRYPTO_DIR_ENCRYPT:
        // 블록 단위로 암호화
        for(i = 0; i < in_len; i += block_size) {
            ret = MG_Crypto_BlockCipher_Encrypt(ctx, in, out);
            if(ret != MG_SUCCESS) {
                return ret;
            }
            in += block_size;
            out += block_size;
            *out_len += block_size;
        }
        break;
    case MG_CRYPTO_DIR_DECRYPT:
        // 블록 단위로 복호화
        for(i = 0; i < in_len; i += block_size) {
            ret = MG_Crypto_BlockCipher_Decrypt(ctx, in, out);
            if(ret != MG_SUCCESS) {
                return ret;
            }
            in += block_size;
            out += block_size;
            *out_len += block_size;
        }
        break;
    }

    return ret;
}

int32_t MG_Crypto_EncryptInit(mg_cipher_ctx* ctx,
                              const uint8_t* key,
                              const uint32_t key_len,
                              const uint32_t algID,
                              const uint32_t dir,
                              const mg_cipher_param* param) {
    int32_t ret = 0;

    if(ctx == NULL || key == NULL || param == NULL) {
        return MG_FAIL; // todo: change error code
    }
    // if(key_len > 32) {
    //     return MG_FAIL; // todo: change error code
    // }
    // if(key_len == 0) {
    //     return MG_FAIL; // todo: change error code
    // }

    memset(ctx, 0, sizeof(mg_cipher_ctx)); // ctx 초기화

    // mg_cipher_ctx 구조체 값 설정
    memcpy(&ctx->param, param, sizeof(mg_cipher_param));
    ctx->algID = algID;
    ctx->dir = dir;
    ctx->block_size = 16; // AES, ARIA, LEA는 모두 16byte
    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;
    memset(ctx->buf, 0, sizeof(ctx->buf)); // buffer 초기화 (이거 sizeof(ctx->buf) 얼만지 확인해보기)
    ctx->buf_len = 0;                      // buffer 초기화
    uint32_t key_bit = key_len * 8;        // key_len is byte -> ARIA, AES에서 bit로 변환해서 사용

    switch(algID) { // algID에 따라 라운드 키 생성
    case MG_CRYPTO_ID_ARIA:
        ret = MG_Crypto_ARIA_KeySetup(&ctx->key_ctx.aria, key, key_bit, dir);
        break;
    case MG_CRYPTO_ID_LEA:
        ret = MG_Crypto_LEA_KeySetup(&ctx->key_ctx.lea, key, key_len);
        break;
    case MG_CRYPTO_ID_AES:
        ret = MG_Crypto_AES_KeySetup(&ctx->key_ctx.aes, key, key_bit, dir);
        break;
    default:
        ret = MG_FAIL; // todo: change error code
        break;
    }
    return ret;
}

int32_t MG_Crypto_EncryptUpdate(mg_cipher_ctx* ctx,
                                const uint8_t* in,
                                const uint32_t in_len,
                                uint8_t* out,
                                uint32_t* out_len) {

    int32_t ret = 0;

    if(ctx == NULL || in == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    // 운영모드에 따라 처리
    switch(ctx->param.modeID) {
    case MG_CRYPTO_MODE_ECB:
        ret = MG_Crypto_Block_ECB(ctx, in, in_len, out, out_len);
        break;
    default:
        ret = MG_FAIL; // todo : change error code (운용모드가 잘못됨)
        break;
    }

    // 남은 블록 buf에 저장
    ctx->buf_len = in_len % ctx->block_size;
    if(ctx->buf_len > 0) {
        memcpy(ctx->buf, in + in_len - ctx->buf_len, ctx->buf_len);
    }

    return ret;
}

int32_t MG_Crypto_EncryptFinal(mg_cipher_ctx* ctx,
                               uint8_t* out,
                               uint32_t* out_len) {
    int32_t ret = 0;

    if(ctx == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    // 남은 블록 처리
    // buf는 buf_len을 제외하면 0으로 초기화 되어있음
    if(ctx->buf_len > 0) {
        ret = MG_Crypto_Core(ctx, ctx->buf, out, ctx->dir);
        if(ret != MG_SUCCESS) {
            return ret;
        }
        *out_len += ctx->buf_len;
    }

    return ret;
}