#include "mg_kdf.h"

int32_t pbkdf2_test() {
    int32_t ret = 0;
    printf("* PBKDF2 test *\n");

    // PBKDF2 Test Vector Test Case 4
    unsigned char password[] = "passwordPASSWORDpassword";
    unsigned char salt[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    int iter = 4096;
    unsigned char key[25] = {0};
    int keyLen = sizeof(key);

    unsigned char expected_key[25] = {
        0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
        0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c};

    ret = MG_Crypto_KDF(password, strlen((char*)password), salt, strlen((char*)salt), iter, key, keyLen, MG_KDF_ID_PBKDF2);

    if(ret != MG_SUCCESS) {
        printf("PBKDF2 test failed with error code: %d\n", ret);
        return -1; // 실패
    }

    // 결과 비교
    for(int i = 0; i < keyLen; i++) {
        if(key[i] != expected_key[i]) {
            printf("PBKDF2 test failed at index %d: expected %02X, got %02X\n", i, expected_key[i], key[i]);
            return -1; // 실패
        }
    }

    // 성공 메시지 출력
    printf("PBKDF2 Test Passed!\n");
    return 0; // 성공
}

int main() {
    int32_t ret = 0;

    ret = pbkdf2_test();

    return ret;
}