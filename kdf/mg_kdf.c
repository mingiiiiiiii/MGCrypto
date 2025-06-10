#include "mg_kdf.h"

int32_t MG_Crypto_KDF(unsigned char* password,
                      int passwordLen,
                      unsigned char* salt,
                      int saltLen,
                      int iter,
                      unsigned char* key,
                      int keyLen,
                      const uint32_t kdf_id) {

    if(password == NULL || salt == NULL || key == NULL || passwordLen <= 0 || saltLen <= 0 || keyLen <= 0) {
        printf("Invalid parameters: password, salt, or key is NULL or has invalid length.\n");
        return MG_FAIL; // Invalid parameters
    }
    if(iter <= 0) {
        printf("Invalid iteration count: %d\n", iter);
        return MG_FAIL; // Invalid iteration count
    }

    int32_t ret = 0;

    switch(kdf_id) {
    case MG_KDF_ID_PBKDF2:
        return KISA_PBKDF2(password, passwordLen, salt, saltLen, iter, key, keyLen);
    default:
        return MG_FAIL; // KDF ID Error
    }

    return ret;
}