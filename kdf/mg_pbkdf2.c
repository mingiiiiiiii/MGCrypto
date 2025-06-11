#include <stdio.h>
// #include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include "mg_sha2.h"
#include "mg_hmac.h"
#include "mg_pbkdf2.h"

#define MAX_HMAC_BLOCK 128

int KISA_PBKDF2(unsigned char* password,
                int passwordLen,
                unsigned char* salt,
                int saltLen,
                int iter,
                unsigned char* key,
                int keyLen) {
    unsigned char* salt_and_int = NULL;
    int saltIntLen;
    unsigned char U[64]; // Max Digest Size
    int ULen = SHA256_DIGEST_LENGTH;
    unsigned char T[64]; // Max Digest Size
    int l, r, hLen = SHA256_DIGEST_LENGTH, outInd = 0;
    int i, j, k, retcode = 0;

    HMAC_SHA256_CTX hmac = {
        0x00,
    };

    l = keyLen / hLen + (keyLen % hLen == 0 ? 0 : 1);
    r = keyLen - ((l - 1) * hLen);

    if(r < 0)
        return 1;

    salt_and_int = (unsigned char*)malloc(saltLen + 4);

    if(salt_and_int == NULL) {
        retcode = 1;
        goto ret;
    }

    memcpy(salt_and_int, salt, saltLen);

    for(i = 1; i <= l; i++) {
        saltIntLen = saltLen + 4;

        salt_and_int[saltLen] = (i >> 24) & 0xFF;
        salt_and_int[saltLen + 1] = (i >> 16) & 0xFF;
        salt_and_int[saltLen + 2] = (i >> 8) & 0xFF;
        salt_and_int[saltLen + 3] = (i) & 0xFF;

        hmac_sha256_Init(&hmac, password, passwordLen);
        hmac_sha256_Update(&hmac, salt_and_int, saltIntLen);
        hmac_sha256_Final(&hmac, U);

        memset(T, 0x00, 64);

        for(k = 0; k < ULen; k++)
            T[k] ^= U[k];

        for(j = 1; j < iter; j++) {
            hmac_sha256_Init(&hmac, password, passwordLen);
            hmac_sha256_Update(&hmac, U, ULen);
            hmac_sha256_Final(&hmac, U);

            for(k = 0; k < ULen; k++)
                T[k] ^= U[k];
        }
        memcpy(key + (outInd), T, (i == l) ? r : ULen);
        outInd += (i == l) ? r : ULen;
    }

    retcode = 0;

ret:
    if(salt_and_int)
        free(salt_and_int);

    return retcode;
}
