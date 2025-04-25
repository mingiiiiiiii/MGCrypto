#include "mg_blockcipher.h"

// init -> update -> final
// init: 키 설정, mode 설정?
/*
    상대가 뭘 입력하지?
    어떤 암호 알고리즘(+어떤 보안강도) 쓸건지, 운용모드는 뭐 쓸건지,
    평문, 키, IV, (+패딩?)

    -> 평문, 평문 길이, 암호키, 암호키 길이, 암호알고리즘 식별, IV, IV 길이, 운용모드, 패딩

*/

// int32_t MG_Crypto_EncryptInit();
// int32_t MG_Crypto_EncryptUpdate();
// int32_t MG_Crypto_EncryptFinal();
// int32_t MG_Crypto_Encrypt();

// int32_t MG_Crypto_DecryptInit();
// int32_t MG_Crypto_DecryptUpdate();
// int32_t MG_Crypto_DecryptFinal();
// int32_t MG_Crypto_Decrypt();

// 블록암호 암호화 함수를 호출하는 함수
// 한 블록 in에 대해 암호화 수행 후 out으로 전달
int32_t MG_Crypto_BlockCipher_Encrypt(mg_cipher_ctx* ctx,
                                      const uint8_t* in,
                                      uint8_t* out) {
    int32_t ret = 0;
    switch(ctx->alg_ID) {
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

// 블록암호 복호화 함수를 호출하는 함수
int32_t MG_Crypto_BlockCipher_Decrypt(mg_cipher_ctx* ctx,
                                      const uint8_t* in,
                                      uint8_t* out) {
    int32_t ret = 0;
    switch(ctx->alg_ID) {
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
//     switch(ctx->alg_ID) {
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

// 운용모드에 따라 처리
// Update, Final에서 사용
// Final에서 추가 블록 처리를 위해 따로 구현
int32_t MG_Crypto_BlockCipher_Mode(mg_cipher_ctx* ctx,
                                   const uint8_t* in,
                                   const uint32_t in_len,
                                   uint8_t* out,
                                   uint32_t* out_len) {
    int32_t ret = 0;

    if(ctx == NULL || in == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    switch(ctx->param.modeID) {
    case MG_CRYPTO_MODE_ECB:
        ret = MG_Crypto_BlockCipher_ECB(ctx, in, in_len, out, out_len);
        break;
    case MG_CRYPTO_MODE_CBC:
        ret = MG_Crypto_BlockCipher_CBC(ctx, in, in_len, out, out_len);
        break;
    default:
        ret = MG_FAIL; // todo: change error code
        break;
    }

    return ret;
}

// ECB 모드 암/복호화
// in_len에 대해 블록 단위로 암/복호화 ECB Mode 수행
// in_len이 block_len보다 작아도 1번은 수행함
int32_t MG_Crypto_BlockCipher_ECB(mg_cipher_ctx* ctx,
                                  const uint8_t* in,
                                  const uint32_t in_len,
                                  uint8_t* out,
                                  uint32_t* out_len) {
    int32_t ret = 0;

    uint32_t i = 0;
    uint32_t block_len = ctx->block_len;

    if(ctx == NULL || in == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    switch(ctx->dir) {
    case MG_CRYPTO_DIR_ENCRYPT:
        // 블록 단위로 암호화
        for(i = 0; i < in_len; i += block_len) {
            ret = MG_Crypto_BlockCipher_Encrypt(ctx, in, out);
            if(ret != MG_SUCCESS) {
                return ret;
            }
            in += block_len;
            out += block_len;
            *out_len += block_len;
        }
        break;
    case MG_CRYPTO_DIR_DECRYPT:
        // 블록 단위로 복호화
        for(i = 0; i < in_len; i += block_len) {
            ret = MG_Crypto_BlockCipher_Decrypt(ctx, in, out);
            if(ret != MG_SUCCESS) {
                return ret;
            }
            in += block_len;
            out += block_len;
            *out_len += block_len;
        }
        break;
    }

    return ret;
}

// CBC 모드 암/복호화
// in_len에 대해 블록 단위로 암/복호화 ECB Mode 수행
// in_len이 block_len보다 작아도 1번은 수행함
int32_t MG_Crypto_BlockCipher_CBC(mg_cipher_ctx* ctx,
                                  const uint8_t* in,
                                  const uint32_t in_len,
                                  uint8_t* out,
                                  uint32_t* out_len) {
    int32_t ret = 0;

    uint32_t i = 0;
    uint32_t block_len = ctx->block_len;

    uint8_t iv_tmp[16] = {0};                 // IV 저장할 임시 버퍼
    memcpy(iv_tmp, ctx->param.iv, block_len); // IV 복사 (처음 블록에 사용)

    if(ctx == NULL || in == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    switch(ctx->dir) {
    case MG_CRYPTO_DIR_ENCRYPT:
        // 블록 단위로 암호화
        for(i = 0; i < in_len; i += block_len) {
            // IV와 평문 XOR
            for(uint32_t j = 0; j < block_len; j++) {
                iv_tmp[j] ^= in[j];
            }
            // IV 암호화
            ret = MG_Crypto_BlockCipher_Encrypt(ctx, iv_tmp, out);
            if(ret != MG_SUCCESS) {
                goto end;
            }
            // 암호문을 IV로 저장
            memcpy(iv_tmp, out, block_len);

            in += block_len;
            out += block_len;
            *out_len += block_len;
        }
        break;
    case MG_CRYPTO_DIR_DECRYPT:
        // 블록 단위로 복호화
        for(i = 0; i < in_len; i += block_len) {
            ret = MG_Crypto_BlockCipher_Decrypt(ctx, in, out);
            if(ret != MG_SUCCESS) {
                goto end;
            }
            // 복호문과 IV XOR
            for(uint32_t j = 0; j < block_len; j++) {
                out[j] ^= iv_tmp[j];
            }
            // 이전 블록의 암호문은 다음 블록의 IV로 사용
            memcpy(iv_tmp, in, block_len);

            in += block_len;
            out += block_len;
            *out_len += block_len;
        }
        break;
    }

end:
    memset(iv_tmp, 0, sizeof(iv_tmp)); // IV 임시 버퍼 초기화
    return ret;
}

// buf를 입력받아 패딩 처리 후 패딩 길이 반환
// ZERO 패딩 -> buf_len이 0이라면 추가로 안해도 됨
// ONEZERO 패딩 -> buf_len이 0이라면 추가 블럭에 패딩해야함
// PKCS 패딩 -> buf_len이 0이라면 추가 블럭에 패딩해야함
int32_t MG_Crypto_BlockCipher_Padding(uint8_t* buf,
                                      const uint32_t buf_len,
                                      const uint32_t block_len,
                                      const uint32_t paddingID) {

    int i, padding_len;
    padding_len = block_len - buf_len; // 패딩해야 할 byte 수

    // Encrypt_Update의 구조 상 buf_len = 0인 경우, 혹은 아닌 경우만 존재
    // buf_len = 0인 경우 -> padding_len = block_len
    switch(paddingID) {
    case MG_CRYPTO_PADDING_NO:
        padding_len = 0; // 패딩 없음
        break;
    case MG_CRYPTO_PADDING_ZERO:
        if(buf_len == 0) {   // 평문 길이가 블록의 배수인 경우
            padding_len = 0; // 패딩 없음
        } else {
            for(i = 0; i < padding_len; i++) {
                buf[buf_len + i] = 0x00; // 0으로 패딩
            }
        }
        break;
    case MG_CRYPTO_PADDING_ONEZERO:
        buf[buf_len] = 0x80; // 1로 패딩
        for(i = 1; i < padding_len; i++) {
            buf[buf_len + i] = 0x00; // 0으로 패딩
        }
        break;
    case MG_CRYPTO_PADDING_PKCS:
        for(i = 0; i < padding_len; i++) {
            buf[buf_len + i] = padding_len; // 패딩 길이로 패딩

            return MG_SUCCESS;
        }
        break;
    }

    return padding_len; // 패딩 길이 리턴
}

// Init 단계 -> 파라미터 설정, 키 설정
int32_t MG_Crypto_EncryptInit(mg_cipher_ctx* ctx,
                              const uint8_t* key,
                              const uint32_t key_len,
                              const uint32_t alg_ID,
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
    ctx->alg_ID = alg_ID;
    ctx->dir = dir;
    ctx->block_len = 16; // AES, ARIA, LEA는 모두 16byte

    memcpy(ctx->key, key, key_len); // key 복사, 길이 설정
    ctx->key_len = key_len;
    uint32_t key_bit = key_len * 8; // key_len is byte -> ARIA, AES에서 bit로 변환해서 사용

    memset(ctx->buf, 0, sizeof(ctx->buf)); // buffer 초기화 (이거 sizeof(ctx->buf) 얼만지 확인해보기)
    ctx->buf_len = 0;                      // buffer 초기화

    switch(alg_ID) { // alg_ID에 따라 라운드 키 생성
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

// Update 단계 -> 실제 암호화 수행
int32_t MG_Crypto_EncryptUpdate(mg_cipher_ctx* ctx,
                                const uint8_t* in,
                                const uint32_t in_len,
                                uint8_t* out,
                                uint32_t* out_len) {

    int32_t ret = 0;

    if(ctx == NULL || in == NULL || out == NULL || out_len == NULL) {
        ret = MG_FAIL; // todo: change error code
        goto end;
    }
    if(in_len < ctx->block_len) {
        // 입력값(평문)이 한블록 크기보다 작은 경우 -> buf에 저장 후 EncryptFinal에서 처리
        ctx->buf_len = in_len;
        memcpy(ctx->buf, in, in_len); // 남은 블록 buf에 저장
        goto end;
    }

    ret = MG_Crypto_BlockCipher_Mode(ctx, in, in_len, out, out_len);
    if(ret != MG_SUCCESS) {
        *out_len = 0; // 암호화 실패 시 out_len 초기화
        goto end;
    }

    // 남은 블록 buf에 저장
    ctx->buf_len = in_len % ctx->block_len;
    if(ctx->buf_len > 0) {
        memcpy(ctx->buf, in + in_len - ctx->buf_len, ctx->buf_len);
    }

end:
    return ret;
}

// Final 단계 -> 남은 블록 처리 및 패딩
int32_t MG_Crypto_EncryptFinal(mg_cipher_ctx* ctx,
                               uint8_t* out,
                               uint32_t* out_len) {
    int32_t ret = 0;
    int32_t padding_len;
    uint8_t tmp[16] = {0}; // 패딩 처리할 때 사용
    uint32_t tmp_len = 0;

    if(ctx == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    // 남은 블록 패딩, 운용모드 수행
    // buf는 buf_len을 제외하면 0으로 초기화 되어있음
    // 평문 길이가 블록 길이의 배수일 때
    //    No, Zero는 새로운 블록 필요 없음
    //    OneZero, PKCS는 새로운 블록 필요
    if((*out_len < ctx->block_len) && (ctx->param.paddingID == MG_CRYPTO_PADDING_NO)) {
        // 평문 길이가 1 블럭보다 작은데 패딩이 없는 경우 -> error!
        // 즉, Update에서 암/복호화 생략하고, 평문 데이터는 모두 buf에 저장하고, 유효한 데이터가 없는 상태
        ret = MG_FAIL; // todo: change error code
        goto end;
    }

    padding_len = MG_Crypto_BlockCipher_Padding(ctx->buf, ctx->buf_len, ctx->block_len, ctx->param.paddingID);

    if(padding_len == 0) {
        goto end;
    } else {
        // 패딩 된 데이터 운영모드 처리
        ret = MG_Crypto_BlockCipher_Mode(ctx, ctx->buf, padding_len, tmp, &tmp_len);
    }

    if(ret != MG_SUCCESS) {
        goto end;
    }

    memcpy(out + *out_len, tmp, tmp_len); // 패딩 된 데이터 복사
    *out_len += tmp_len;                  // out_len -> (유효한 데이터 길이)

end:
    memset(tmp, 0, sizeof(tmp)); // tmp 초기화
    return ret;
}

/// @brief 1회성 암호화 helper: init→update→final을 한 번에 호출
/// @param key           : 비밀키 버퍼
/// @param key_len       : 비밀키 길이 (byte)
/// @param alg_ID         : 알고리즘 ID (MG_CRYPTO_ID_…)
/// @param dir           : MG_Crypto_ENCRYPT
/// @param param         : 암호 파라미터 (IV, 모드, 패딩 등)
/// @param in            : 평문 버퍼
/// @param in_len        : 평문 길이 (byte)
/// @param out           : 암호문 출력 버퍼
/// @param out_len       : [out] 실제 출력된 암호문 길이 (byte)
/// @return MG_SUCCESS (0) 이외는 실패 코드
int32_t MG_Crypto_Encrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint32_t in_len,
                          uint8_t* out,
                          uint32_t* out_len) {
    int32_t ret = 0;

    mg_cipher_ctx ctx;
    uint32_t dir = MG_CRYPTO_DIR_ENCRYPT;

    // 1) Init
    ret = MG_Crypto_EncryptInit(&ctx, key, key_len, alg_ID, dir, param);
    if(ret != MG_SUCCESS) {
        fprintf(stderr, "EncryptionInit failed\n");
        goto end;
    }

    // 2) Update
    ret = MG_Crypto_EncryptUpdate(&ctx, in, in_len, out, out_len);
    if(ret != MG_SUCCESS) {
        fprintf(stderr, "EncryptionUpdate failed\n");
        goto end;
    }

    // 3) Final (패딩 + 남은 블록 처리)
    ret = MG_Crypto_EncryptFinal(&ctx, out, out_len);
    if(ret != MG_SUCCESS) {
        fprintf(stderr, "EncryptionFinal failed\n");
        goto end;
    }

end:
    memset(&ctx, 0, sizeof(mg_cipher_ctx)); // ctx 초기화
    return ret;
}

// Init 단계 -> 파라미터 설정, 키 설정
int32_t MG_Crypto_DecryptInit(mg_cipher_ctx* ctx,
                              const uint8_t* key,
                              const uint32_t key_len,
                              const uint32_t alg_ID,
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
    ctx->alg_ID = alg_ID;
    ctx->dir = dir;
    ctx->block_len = 16; // AES, ARIA, LEA는 모두 16byte

    memcpy(ctx->key, key, key_len); // key 복사, 길이 설정
    ctx->key_len = key_len;
    uint32_t key_bit = key_len * 8; // key_len is byte -> ARIA, AES에서 bit로 변환해서 사용

    memset(ctx->buf, 0, sizeof(ctx->buf)); // buffer 초기화 (이거 sizeof(ctx->buf) 얼만지 확인해보기)
    ctx->buf_len = 0;                      // buffer 초기화

    switch(alg_ID) { // alg_ID에 따라 라운드 키 생성
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

// Update 단계 -> 실제 암호화 수행
int32_t MG_Crypto_DecryptUpdate(mg_cipher_ctx* ctx,
                                const uint8_t* in,
                                const uint32_t in_len,
                                uint8_t* out,
                                uint32_t* out_len) {

    int32_t ret = 0;

    if(ctx == NULL || in == NULL || out == NULL || out_len == NULL) {
        ret = MG_FAIL; // todo: change error code
        goto end;
    }

    ret = MG_Crypto_BlockCipher_Mode(ctx, in, in_len, out, out_len);
    if(ret != MG_SUCCESS) {
        *out_len = 0; // 복호화 실패 시 out_len 초기화
        goto end;
    }

end:
    return ret;
}

// Final 단계 -> 마지막 블록 패딩 제거
int32_t MG_Crypto_DecryptFinal(mg_cipher_ctx* ctx,
                               uint8_t* out,
                               uint32_t* out_len) {
    int32_t ret = 0;
    int32_t padding_len = 0;
    uint32_t i;

    if(ctx == NULL || out == NULL || out_len == NULL) {
        return MG_FAIL; // todo: change error code
    }

    // onezero, pkcs만 처리해주면 됨
    switch(ctx->param.paddingID) {
    case MG_CRYPTO_PADDING_ONEZERO:
        i = *out_len - 1;
        while(out[i--] == 0x00) {
            padding_len++; // 패딩 길이 구하기 (0x80 나오기 전엔 모두 0x00)
        }
        *out_len -= (padding_len + 1); // 패딩 길이만큼 out_len 줄이기 (0x80도 없애줘야 하므로 +1)
        // todo : i가 음수가 되는 경우는 에러 처리
        break;
    case MG_CRYPTO_PADDING_PKCS:
        padding_len = out[*out_len - 1]; // 패딩 길이
        *out_len -= padding_len;         // 패딩 길이만큼 out_len 줄이기
        break;
    }

    return ret;
}

/// @brief 1회성 복호화 helper: init→update→final을 한 번에 호출
/// @param key           : 비밀키 버퍼
/// @param key_len       : 비밀키 길이 (byte)
/// @param alg_ID         : 알고리즘 ID (MG_CRYPTO_ID_…)
/// @param dir           : MG_Crypto_Decrypt
/// @param param         : 암호 파라미터 (IV, 모드, 패딩 등)
/// @param in            : 암호문 버퍼
/// @param in_len        : 암호문 길이 (byte)
/// @param out           : 복호화된 평문 출력 버퍼
/// @param out_len       : [out] 실제 복호화되어 출력된 평문 길이 (byte)
/// @return MG_SUCCESS (0) 이외는 실패 코드
int32_t MG_Crypto_Decrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint32_t in_len,
                          uint8_t* out,
                          uint32_t* out_len) {
    int32_t ret = 0;

    mg_cipher_ctx ctx;
    uint32_t dir = MG_CRYPTO_DIR_DECRYPT;

    // 1) Init
    ret = MG_Crypto_DecryptInit(&ctx, key, key_len, alg_ID, dir, param);
    if(ret != MG_SUCCESS) {
        goto end;
    }

    // 2) Update
    ret = MG_Crypto_DecryptUpdate(&ctx, in, in_len, out, out_len);
    if(ret != MG_SUCCESS) {
        goto end;
    }

    // 3) Final (패딩 + 남은 블록 처리)
    ret = MG_Crypto_DecryptFinal(&ctx, out, out_len);
    if(ret != MG_SUCCESS) {
        goto end;
    }

end:
    memset(&ctx, 0, sizeof(mg_cipher_ctx)); // ctx 초기화
    return ret;
}