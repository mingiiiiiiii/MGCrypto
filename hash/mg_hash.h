#ifndef MG_HASH_H
#define MG_HASH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

// #include "mg_lsh.h"
#include "mg_lsh512.h"
#include "mg_sha3.h"
#include "mg_sha2.h"
#include "mg_crypto.h"

/**
 * @brief MG_Crypto_Hash function (SHA256, SHA3, LSH512)
 * @param in Pointer to the input data to be hashed
 * @param in_len Length of the input data in bytes
 * @param out Pointer to the output buffer where the hash will be stored
 * @param out_len Length of the output buffer in bytes
 * @param hash_id Identifier for the hash algorithm to be used (MG_HASH_ID_*)
 * @return int32_t Returns MG_SUCCESS on success, or an error code on failure
 */
int32_t MG_Crypto_Hash(const uint8_t* in,
                       const uint32_t in_len,
                       uint8_t* out,
                       const uint32_t out_len,
                       const uint32_t hash_id);

#endif // MG_HASH_H