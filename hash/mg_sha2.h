/**
 * Copyright (c) 2000-2001 Aaron D. Gifford
 * Copyright (c) 2013-2014 Pavol Rusnak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _MG_SHA2_H_
#define _MG_SHA2_H_

#include <stdint.h>
#include <stddef.h>
#include "byte_order.h"

#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_STRING_LENGTH (SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH 128
#define SHA512_DIGEST_LENGTH 64
#define SHA512_DIGEST_STRING_LENGTH (SHA512_DIGEST_LENGTH * 2 + 1)

#define SHA384_BLOCK_LENGTH SHA512_BLOCK_LENGTH
#define SHA384_DIGEST_LENGTH 48
#define SHA384_DIGEST_STRING_LENGTH (SHA384_DIGEST_LENGTH * 2 + 1)

typedef struct _SHA256_CTX {
    uint32_t state[8];
    uint64_t bitcount;
    uint32_t buffer[SHA256_BLOCK_LENGTH / sizeof(uint32_t)];
} SHA256_CTX;
typedef struct _SHA512_CTX {
    uint64_t state[8];
    uint64_t bitcount[2];
    uint64_t buffer[SHA512_BLOCK_LENGTH / sizeof(uint64_t)];
} SHA512_CTX;

extern const uint32_t sha256_initial_hash_value[8];
extern const uint64_t sha512_initial_hash_value[8];

void sha256_Transform(const uint32_t* state_in,
                      const uint32_t* data,
                      uint32_t* state_out);
void sha256_Init(SHA256_CTX*);
void sha256_Update(SHA256_CTX*,
                   const uint8_t*,
                   size_t);
void sha256_Final(SHA256_CTX*,
                  uint8_t[SHA256_DIGEST_LENGTH]);
void sha256_Raw(const uint8_t* data,
                size_t len,
                uint8_t digest[SHA256_DIGEST_LENGTH]);

void sha512_Transform(const uint64_t* state_in,
                      const uint64_t* data,
                      uint64_t* state_out);
void sha512_Init(SHA512_CTX*);
void sha512_Update(SHA512_CTX*,
                   const uint8_t*,
                   size_t);
void sha512_Final(SHA512_CTX*,
                  uint8_t[SHA512_DIGEST_LENGTH]);
void sha512_Raw(const uint8_t* data,
                size_t len,
                uint8_t digest[SHA512_DIGEST_LENGTH]);

void sha384_Init(SHA512_CTX*);
void sha384_Update(SHA512_CTX*,
                   const uint8_t*,
                   size_t);
void sha384_Final(SHA512_CTX*,
                  uint8_t[SHA384_DIGEST_LENGTH]);
void sha384_Raw(const uint8_t* data,
                size_t len,
                uint8_t digest[SHA384_DIGEST_LENGTH]);

#endif
