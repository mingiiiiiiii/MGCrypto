#include "mg_hash.h"

int32_t MG_Crypto_Hash(const uint8_t* in,
                       const uint64_t in_len,
                       uint8_t* out,
                       const uint32_t out_len,
                       const uint32_t hash_id) {
    int32_t ret = 0;

    if(in == NULL || out == NULL || in_len == 0 || out_len == 0) {
        return MG_FAIL; // todo: change error code
    }

    switch(hash_id) {
    case MG_HASH_ID_SHA2_256:
        sha256_Raw(in, in_len, out);
        ret = MG_SUCCESS;
        break;
    case MG_HASH_ID_SHA2_384:
        sha384_Raw(in, in_len, out);
        ret = MG_SUCCESS;
        break;
    case MG_HASH_ID_SHA2_512:
        sha512_Raw(in, in_len, out);
        ret = MG_SUCCESS;
        break;
    case MG_HASH_ID_SHA3_224:
        // sha3에서 in은 바뀌지 않음 (const 유지)
        ret = sha3_hash(out, out_len, (uint8_t*)in, in_len, KECCAK_SHA3_224, SHA3_SHAKE_NONE);
        break;
    case MG_HASH_ID_SHA3_256:
        ret = sha3_hash(out, out_len, (uint8_t*)in, in_len, KECCAK_SHA3_256, SHA3_SHAKE_NONE);
        break;
    case MG_HASH_ID_SHA3_384:
        ret = sha3_hash(out, out_len, (uint8_t*)in, in_len, KECCAK_SHA3_384, SHA3_SHAKE_NONE);
        break;
    case MG_HASH_ID_SHA3_512:
        ret = sha3_hash(out, out_len, (uint8_t*)in, in_len, KECCAK_SHA3_512, SHA3_SHAKE_NONE);
        break;
    case MG_HASH_ID_SHAKE128:
        ret = sha3_hash(out, out_len, (uint8_t*)in, in_len, KECCAK_SHAKE128, SHA3_SHAKE_USE);
        break;
    case MG_HASH_ID_SHAKE256:
        ret = sha3_hash(out, out_len, (uint8_t*)in, in_len, KECCAK_SHAKE256, SHA3_SHAKE_USE);
        break;
    case MG_HASH_ID_LSH512:
        ret = lsh512_digest(LSH_TYPE_512_512, in, in_len * 8, out); // in_len은 바이트 단위이므로 비트로 변환
        if(ret != LSH_SUCCESS) {
            return MG_FAIL; // todo: change error code
        }
        break;
    default:
        return MG_FAIL; // Hash ID Error
    }

    return ret;
}
