#ifndef MG_KDF_H
#define MG_KDF_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "mg_pbkdf2.h"
#include "mg_crypto.h"

/**
 * @brief MG_Crypto_KDF function (Key Derivation Function)
 * @param password Pointer to the password used for key derivation
 * @param passwordLen Length of the password in bytes
 * @param salt Pointer to the salt used for key derivation
 * @param saltLen Length of the salt in bytes
 * @param iter Number of iterations for the KDF
 * @param key Pointer to the output buffer where the derived key will be stored
 * @param keyLen Length of the derived key in bytes
 * @param kdf_id Identifier for the KDF algorithm to be used (MG_KDF_ID_*)
 * @return int32_t Returns MG_SUCCESS on success, or an error code on failure
 */
int32_t MG_Crypto_KDF(unsigned char* password,
                      int passwordLen,
                      unsigned char* salt,
                      int saltLen,
                      int iter,
                      unsigned char* key,
                      int keyLen,
                      const uint32_t kdf_id);

#endif // MG_HASH_H