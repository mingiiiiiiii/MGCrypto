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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string.h>

#include "mg_hmac.h"
// #include "memzero.h"
// #include "options.h"

int32_t MG_Crypto_HMAC(const uint8_t* key,
                       const uint32_t keylen,
                       const uint8_t* msg,
                       const uint32_t msglen,
                       uint8_t* hmac,
                       const uint32_t hmac_id) {
    int32_t ret = 0;

    switch(hmac_id) {
    case MG_HMAC_ID_HMAC_SHA2_256:
        hmac_sha256(key, keylen, msg, msglen, hmac);
        break;
    case MG_HMAC_ID_HMAC_SHA2_384:
        hmac_sha384(key, keylen, msg, msglen, hmac);
        break;
    case MG_HMAC_ID_HMAC_SHA2_512:
        hmac_sha512(key, keylen, msg, msglen, hmac);
        break;
    default:
        return MG_FAIL;
        // Error: Unsupported HMAC ID
    }

    return ret;
}

// SHA2-256
void hmac_sha256_Init(HMAC_SHA256_CTX* hctx,
                      const uint8_t* key,
                      const uint32_t keylen) {
    uint8_t i_key_pad[SHA256_BLOCK_LENGTH];
    // memzero(i_key_pad, SHA256_BLOCK_LENGTH);
    memset(i_key_pad, 0, SHA256_BLOCK_LENGTH);
    if(keylen > SHA256_BLOCK_LENGTH) {
        sha256_Raw(key, keylen, i_key_pad);
    } else {
        memcpy(i_key_pad, key, keylen);
    }
    for(int i = 0; i < SHA256_BLOCK_LENGTH; i++) {
        hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
        i_key_pad[i] ^= 0x36;
    }
    sha256_Init(&(hctx->ctx));
    sha256_Update(&(hctx->ctx), i_key_pad, SHA256_BLOCK_LENGTH);
    // memzero(i_key_pad, sizeof(i_key_pad));
    memset(i_key_pad, 0, sizeof(i_key_pad));
}

void hmac_sha256_Update(HMAC_SHA256_CTX* hctx,
                        const uint8_t* msg,
                        const uint32_t msglen) {
    sha256_Update(&(hctx->ctx), msg, msglen);
}

void hmac_sha256_Final(HMAC_SHA256_CTX* hctx,
                       uint8_t* hmac) {
    sha256_Final(&(hctx->ctx), hmac);
    sha256_Init(&(hctx->ctx));
    sha256_Update(&(hctx->ctx), hctx->o_key_pad, SHA256_BLOCK_LENGTH);
    sha256_Update(&(hctx->ctx), hmac, SHA256_DIGEST_LENGTH);
    sha256_Final(&(hctx->ctx), hmac);
    // memzero(hctx, sizeof(HMAC_SHA256_CTX));
    memset(hctx, 0, sizeof(HMAC_SHA256_CTX));
}

void hmac_sha256(const uint8_t* key,
                 const uint32_t keylen,
                 const uint8_t* msg,
                 const uint32_t msglen,
                 uint8_t* hmac) {
    HMAC_SHA256_CTX hctx;
    hmac_sha256_Init(&hctx, key, keylen);
    hmac_sha256_Update(&hctx, msg, msglen);
    hmac_sha256_Final(&hctx, hmac);
}

// SHA2-384
void hmac_sha384_Init(HMAC_SHA512_CTX* hctx,
                      const uint8_t* key,
                      const uint32_t keylen) {
    uint8_t i_key_pad[SHA384_BLOCK_LENGTH];
    memset(i_key_pad, 0, SHA384_BLOCK_LENGTH);
    if(keylen > SHA384_BLOCK_LENGTH) {
        sha384_Raw(key, keylen, i_key_pad);
    } else {
        memcpy(i_key_pad, key, keylen);
    }
    for(int i = 0; i < SHA384_BLOCK_LENGTH; i++) {
        hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
        i_key_pad[i] ^= 0x36;
    }
    sha384_Init(&(hctx->ctx));
    sha384_Update(&(hctx->ctx), i_key_pad, SHA384_BLOCK_LENGTH);
    memset(i_key_pad, 0, sizeof(i_key_pad));
}

void hmac_sha384_Update(HMAC_SHA512_CTX* hctx,
                        const uint8_t* msg,
                        const uint32_t msglen) {
    sha384_Update(&(hctx->ctx), msg, msglen);
}

void hmac_sha384_Final(HMAC_SHA512_CTX* hctx,
                       uint8_t* hmac) {
    sha384_Final(&(hctx->ctx), hmac);
    sha384_Init(&(hctx->ctx));
    sha384_Update(&(hctx->ctx), hctx->o_key_pad, SHA384_BLOCK_LENGTH);
    sha384_Update(&(hctx->ctx), hmac, SHA384_DIGEST_LENGTH);
    sha384_Final(&(hctx->ctx), hmac);
    memset(hctx, 0, sizeof(HMAC_SHA512_CTX));
}

void hmac_sha384(const uint8_t* key,
                 const uint32_t keylen,
                 const uint8_t* msg,
                 const uint32_t msglen,
                 uint8_t* hmac) {
    HMAC_SHA512_CTX hctx = {0};
    hmac_sha384_Init(&hctx, key, keylen);
    hmac_sha384_Update(&hctx, msg, msglen);
    hmac_sha384_Final(&hctx, hmac);
}

// SHA2-512
void hmac_sha512_Init(HMAC_SHA512_CTX* hctx,
                      const uint8_t* key,
                      const uint32_t keylen) {
    uint8_t i_key_pad[SHA512_BLOCK_LENGTH];
    // memzero(i_key_pad, SHA512_BLOCK_LENGTH);
    memset(i_key_pad, 0, SHA512_BLOCK_LENGTH);
    if(keylen > SHA512_BLOCK_LENGTH) {
        sha512_Raw(key, keylen, i_key_pad);
    } else {
        memcpy(i_key_pad, key, keylen);
    }
    for(int i = 0; i < SHA512_BLOCK_LENGTH; i++) {
        hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
        i_key_pad[i] ^= 0x36;
    }
    sha512_Init(&(hctx->ctx));
    sha512_Update(&(hctx->ctx), i_key_pad, SHA512_BLOCK_LENGTH);
    // memzero(i_key_pad, sizeof(i_key_pad));
    memset(i_key_pad, 0, sizeof(i_key_pad));
}

void hmac_sha512_Update(HMAC_SHA512_CTX* hctx,
                        const uint8_t* msg,
                        const uint32_t msglen) {
    sha512_Update(&(hctx->ctx), msg, msglen);
}

void hmac_sha512_Final(HMAC_SHA512_CTX* hctx,
                       uint8_t* hmac) {
    sha512_Final(&(hctx->ctx), hmac);
    sha512_Init(&(hctx->ctx));
    sha512_Update(&(hctx->ctx), hctx->o_key_pad, SHA512_BLOCK_LENGTH);
    sha512_Update(&(hctx->ctx), hmac, SHA512_DIGEST_LENGTH);
    sha512_Final(&(hctx->ctx), hmac);
    // memzero(hctx, sizeof(HMAC_SHA512_CTX));
    memset(hctx, 0, sizeof(HMAC_SHA512_CTX));
}

void hmac_sha512(const uint8_t* key,
                 const uint32_t keylen,
                 const uint8_t* msg,
                 const uint32_t msglen,
                 uint8_t* hmac) {
    HMAC_SHA512_CTX hctx = {0};
    hmac_sha512_Init(&hctx, key, keylen);
    hmac_sha512_Update(&hctx, msg, msglen);
    hmac_sha512_Final(&hctx, hmac);
}

// // HMAC_SHA3
// void hmac_sha3_256_Init(HMAC_SHA3_256_CTX* hctx,
//                         const uint8_t* key,
//                         const uint32_t keylen) {
//     uint8_t i_key_pad[SHA3_256_BLOCK_LENGTH] = {
//         0x00,
//     };
//     // memzero(i_key_pad, SHA256_BLOCK_LENGTH);
//     // memset(i_key_pad, 0, SHA3_256_BLOCK_LENGTH);
//     if(keylen > SHA3_256_BLOCK_LENGTH) {
//         sha3_256(key, keylen, i_key_pad);
//     } else {
//         memcpy(i_key_pad, key, keylen);
//     }
//     for(int i = 0; i < SHA3_256_BLOCK_LENGTH; i++) {
//         hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
//         i_key_pad[i] ^= 0x36;
//     }
//     sha3_256_Init(&(hctx->ctx));
//     sha3_Update(&(hctx->ctx), i_key_pad, SHA3_256_BLOCK_LENGTH);

//     // memzero(i_key_pad, sizeof(i_key_pad));
//     memset(i_key_pad, 0, sizeof(i_key_pad));
// }

// void hmac_sha3_256_Update(HMAC_SHA3_256_CTX* hctx,
//                           const uint8_t* msg,
//                           const uint32_t msglen) {
//     sha3_Update(&(hctx->ctx), msg, msglen);
// }

// void hmac_sha3_256_Final(HMAC_SHA3_256_CTX* hctx,
//                          uint8_t* hmac) {
//     sha3_Final(&(hctx->ctx), hmac);
//     sha3_256_Init(&(hctx->ctx));
//     sha3_Update(&(hctx->ctx), hctx->o_key_pad, SHA3_256_BLOCK_LENGTH);
//     sha3_Update(&(hctx->ctx), hmac, sha3_256_hash_size);
//     sha3_Final(&(hctx->ctx), hmac);
//     // memzero(hctx, sizeof(HMAC_SHA256_CTX));
//     memset(hctx, 0, sizeof(HMAC_SHA3_256_CTX));
// }

// void hmac_sha3_256(const uint8_t* key,
//                    const uint32_t keylen,
//                    const uint8_t* msg,
//                    const uint32_t msglen,
//                    uint8_t* hmac) {
//     HMAC_SHA3_256_CTX hctx = {
//         0x00,
//     };
//     hmac_sha3_256_Init(&hctx, key, keylen);
//     hmac_sha3_256_Update(&hctx, msg, msglen);
//     hmac_sha3_256_Final(&hctx, hmac);
// }

// // SHA3-384
// void hmac_sha3_384_Init(HMAC_SHA3_384_CTX* hctx,
//                         const uint8_t* key,
//                         const uint32_t keylen) {
//     uint8_t i_key_pad[SHA3_384_BLOCK_LENGTH] = {
//         0x00,
//     };
//     // memzero(i_key_pad, SHA384_BLOCK_LENGTH);
//     // memset(i_key_pad, 0, SHA3_384_BLOCK_LENGTH);
//     if(keylen > SHA3_384_BLOCK_LENGTH) {
//         sha3_384(key, keylen, i_key_pad);

//     } else {
//         memcpy(i_key_pad, key, keylen);
//     }
//     for(int i = 0; i < SHA3_384_BLOCK_LENGTH; i++) {
//         hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
//         i_key_pad[i] ^= 0x36;
//     }
//     sha3_384_Init(&(hctx->ctx));
//     sha3_Update(&(hctx->ctx), i_key_pad, SHA3_384_BLOCK_LENGTH);

//     // memzero(i_key_pad, sizeof(i_key_pad));
//     memset(i_key_pad, 0, sizeof(i_key_pad));
// }

// void hmac_sha3_384_Update(HMAC_SHA3_384_CTX* hctx,
//                           const uint8_t* msg,
//                           const uint32_t msglen) {
//     sha3_Update(&(hctx->ctx), msg, msglen);
// }

// void hmac_sha3_384_Final(HMAC_SHA3_384_CTX* hctx,
//                          uint8_t* hmac) {
//     sha3_Final(&(hctx->ctx), hmac);
//     sha3_384_Init(&(hctx->ctx));
//     sha3_Update(&(hctx->ctx), hctx->o_key_pad, SHA3_384_BLOCK_LENGTH);
//     sha3_Update(&(hctx->ctx), hmac, sha3_384_hash_size);
//     sha3_Final(&(hctx->ctx), hmac);
//     // memzero(hctx, sizeof(HMAC_SHA384_CTX));
//     memset(hctx, 0, sizeof(HMAC_SHA3_384_CTX));
// }

// void hmac_sha3_384(const uint8_t* key,
//                    const uint32_t keylen,
//                    const uint8_t* msg,
//                    const uint32_t msglen,
//                    uint8_t* hmac) {
//     HMAC_SHA3_384_CTX hctx = {
//         0x00,
//     };
//     hmac_sha3_384_Init(&hctx, key, keylen);
//     hmac_sha3_384_Update(&hctx, msg, msglen);
//     hmac_sha3_384_Final(&hctx, hmac);
// }

// // SHA3-512
// void hmac_sha3_512_Init(HMAC_SHA3_512_CTX* hctx,
//                         const uint8_t* key,
//                         const uint32_t keylen) {
//     uint8_t i_key_pad[SHA3_512_BLOCK_LENGTH] = {
//         0x00,
//     };
//     // memzero(i_key_pad, SHA512_BLOCK_LENGTH);
//     // memset(i_key_pad, 0, SHA3_512_BLOCK_LENGTH);
//     if(keylen > SHA3_512_BLOCK_LENGTH) {
//         sha3_512(key, keylen, i_key_pad);
//     } else {
//         memcpy(i_key_pad, key, keylen);
//     }
//     for(int i = 0; i < SHA3_512_BLOCK_LENGTH; i++) {
//         hctx->o_key_pad[i] = i_key_pad[i] ^ 0x5c;
//         i_key_pad[i] ^= 0x36;
//     }
//     sha3_512_Init(&(hctx->ctx));
//     sha3_Update(&(hctx->ctx), i_key_pad, SHA3_512_BLOCK_LENGTH);

//     // memzero(i_key_pad, sizeof(i_key_pad));
//     memset(i_key_pad, 0, sizeof(i_key_pad));
// }

// void hmac_sha3_512_Update(HMAC_SHA3_512_CTX* hctx,
//                           const uint8_t* msg,
//                           const uint32_t msglen) {
//     sha3_Update(&(hctx->ctx), msg, msglen);
// }

// void hmac_sha3_512_Final(HMAC_SHA3_512_CTX* hctx,
//                          uint8_t* hmac) {
//     sha3_Final(&(hctx->ctx), hmac);
//     sha3_512_Init(&(hctx->ctx));
//     sha3_Update(&(hctx->ctx), hctx->o_key_pad, SHA3_512_BLOCK_LENGTH);
//     sha3_Update(&(hctx->ctx), hmac, sha3_512_hash_size);
//     sha3_Final(&(hctx->ctx), hmac);
//     // memzero(hctx, sizeof(HMAC_SHA512_CTX));
//     memset(hctx, 0, sizeof(HMAC_SHA3_512_CTX));
// }

// void hmac_sha3_512(const uint8_t* key,
//                    const uint32_t keylen,
//                    const uint8_t* msg,
//                    const uint32_t msglen,
//                    uint8_t* hmac) {
//     HMAC_SHA3_512_CTX hctx = {
//         0x00,
//     };
//     hmac_sha3_512_Init(&hctx, key, keylen);
//     hmac_sha3_512_Update(&hctx, msg, msglen);
//     hmac_sha3_512_Final(&hctx, hmac);
// }
