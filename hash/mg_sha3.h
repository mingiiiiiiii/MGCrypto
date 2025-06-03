#ifndef _MG_SHA3_H_
#define _MG_SHA3_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KECCAK_SPONGE_BIT 1600
#define KECCAK_ROUND 24
#define KECCAK_STATE_SIZE 200

#define KECCAK_SHA3_224 224
#define KECCAK_SHA3_256 256
#define KECCAK_SHA3_384 384
#define KECCAK_SHA3_512 512
#define KECCAK_SHAKE128 128
#define KECCAK_SHAKE256 256

#define KECCAK_SHA3_SUFFIX 0x06
#define KECCAK_SHAKE_SUFFIX 0x1F

typedef enum {
    SHA3_OK = 0,
    SHA3_PARAMETER_ERROR = 1,
} SHA3_RETRUN;

typedef enum {
    SHA3_SHAKE_NONE = 0,
    SHA3_SHAKE_USE = 1,
} SHA3_USE_SHAKE;

/**
 * @brief SHA3 hash function
 * @param output Pointer to the output buffer where the hash will be stored
 * @param outLen Length of the output buffer in bytes
 * @param input Pointer to the input data to be hashed
 * @param inLen Length of the input data in bytes
 * @param bitSize Size of the hash output in bits (224, 256, 384, 512)
 * @param useSHAKE Flag to indicate if SHAKE is used (1 for SHAKE, 0 for SHA3)
 */
int sha3_hash(uint8_t* output,
              int outLen,
              uint8_t* input,
              int inLen,
              int bitSize,
              int useSHAKE);

#ifdef __cplusplus
}
#endif

#endif // _MG_SHA3_H_
