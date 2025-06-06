/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT HMAC_SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _MG_HMAC_H_
#define _MG_HMAC_H_

#include <stdint.h>
#include "../hash/mg_sha2.h"
#include "mg_crypto.h"

typedef struct _HMAC_SHA256_CTX {
    uint8_t o_key_pad[SHA256_BLOCK_LENGTH];
    SHA256_CTX ctx;
} HMAC_SHA256_CTX;

typedef struct _HMAC_SHA512_CTX {
    uint8_t o_key_pad[SHA512_BLOCK_LENGTH];
    SHA512_CTX ctx;
} HMAC_SHA512_CTX;

// typedef struct _HMAC_SHA3_256_CTX {
//     uint8_t o_key_pad[SHA3_256_BLOCK_LENGTH];
//     SHA3_CTX ctx;
// } HMAC_SHA3_256_CTX;

// typedef struct _HMAC_SHA3_384_CTX {
//     uint8_t o_key_pad[SHA3_384_BLOCK_LENGTH];
//     SHA3_CTX ctx;
// } HMAC_SHA3_384_CTX;

// typedef struct _HMAC_SHA3_512_CTX {
//     uint8_t o_key_pad[SHA3_512_BLOCK_LENGTH];
//     SHA3_CTX ctx;
// } HMAC_SHA3_512_CTX;

/**
 * @brief MG_Crypto_HMAC api
 * @param key Pointer to the key used for HMAC
 * @param keylen Length of the key in bytes
 * @param msg Pointer to the message to be hashed
 * @param msglen Length of the message in bytes
 * @param hmac Pointer to the output buffer where the HMAC will be stored
 * @param hmac_id Identifier for the HMAC algorithm to be used (MG_HMAC_ID_*).
 */
int32_t MG_Crypto_HMAC(const uint8_t* key,
                       const uint32_t keylen,
                       const uint8_t* msg,
                       const uint32_t msglen,
                       uint8_t* hmac,
                       const uint32_t hmac_id);

void hmac_sha256_Init(HMAC_SHA256_CTX* hctx,
                      const uint8_t* key,
                      const uint32_t keylen);
void hmac_sha256_Update(HMAC_SHA256_CTX* hctx,
                        const uint8_t* msg,
                        const uint32_t msglen);
void hmac_sha256_Final(HMAC_SHA256_CTX* hctx,
                       uint8_t* hmac);
void hmac_sha256(const uint8_t* key,
                 const uint32_t keylen,
                 const uint8_t* msg,
                 const uint32_t msglen,
                 uint8_t* hmac);

void hmac_sha384_Init(HMAC_SHA512_CTX* hctx,
                      const uint8_t* key,
                      const uint32_t keylen);
void hmac_sha384_Update(HMAC_SHA512_CTX* hctx,
                        const uint8_t* msg,
                        const uint32_t msglen);
void hmac_sha384_Final(HMAC_SHA512_CTX* hctx,
                       uint8_t* hmac);
void hmac_sha384(const uint8_t* key,
                 const uint32_t keylen,
                 const uint8_t* msg,
                 const uint32_t msglen,
                 uint8_t* hmac);

void hmac_sha512_Init(HMAC_SHA512_CTX* hctx,
                      const uint8_t* key,
                      const uint32_t keylen);
void hmac_sha512_Update(HMAC_SHA512_CTX* hctx,
                        const uint8_t* msg,
                        const uint32_t msglen);
void hmac_sha512_Final(HMAC_SHA512_CTX* hctx,
                       uint8_t* hmac);
void hmac_sha512(const uint8_t* key,
                 const uint32_t keylen,
                 const uint8_t* msg,
                 const uint32_t msglen,
                 uint8_t* hmac);

#endif
