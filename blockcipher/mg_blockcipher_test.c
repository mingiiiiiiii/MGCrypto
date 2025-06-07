#include "mg_blockcipher.h"
#include "mg_blockcipher_test.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

/// '0'–'9','a'–'f','A'–'F' → 0–15 반환
int32_t hexchar_to_val(const uint8_t c) {
    if(c >= '0' && c <= '9') {
        return c - '0';
    } else if(c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if(c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    // 잘못된 값에 대해서 오류 메시지를 출력하고 프로그램 종료
    fprintf(stderr, "Error: Invalid hex character '%c'\n", c);
    exit(EXIT_FAILURE); // 실패 상태로 종료
}

/// @brief 16진수 문자열(hexlen 짝수) → byte 배열 변환
/// @return 성공하면 변환된 바이트 수, 실패하면 -1
uint32_t hex2bin(const uint8_t* hex,
                 uint8_t* out) {
    size_t hexlen = strlen((const char*)hex);
    if(hexlen % 2) {
        fprintf(stderr, "hex2bin: odd length\n");
    }

    size_t bytes = hexlen / 2;
    for(size_t i = 0; i < bytes; i++) {
        int hi = hexchar_to_val(hex[2 * i]);
        int lo = hexchar_to_val(hex[2 * i + 1]);
        if(hi < 0 || lo < 0) {
            fprintf(stderr, "hex2bin error!\n");
        }
        out[i] = ((hi << 4) & 0xF0) | (lo & 0x0F);
    }
    return (uint32_t)bytes;
}

// 블록암호, 운용모드, KAT
void MG_Crypto_Test_KAT(enum MG_CRYPTO_TEST_ID_KAT test_ID) {
    FILE* fp_req = NULL;
    FILE* fp_rsp = NULL;

    uint32_t mode_ID = 0;
    uint32_t alg_ID = 0;

    switch(test_ID) {
    case MG_CRYPTO_TEST_ID_KAT_AES128_ECB:
        fp_req = fopen("../blockcipher/testvector/AES/AES128(ECB)KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/AES/AES128(ECB)KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_AES;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_AES192_ECB:
        fp_req = fopen("../blockcipher/testvector/AES/AES192(ECB)KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/AES/AES192(ECB)KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_AES;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_AES256_ECB:
        fp_req = fopen("../blockcipher/testvector/AES/AES256(ECB)KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/AES/AES256(ECB)KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_AES;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_AES128_CBC:
        fp_req = fopen("../blockcipher/testvector/AES/AES128(CBC)KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/AES/AES128(CBC)KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_AES;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_AES192_CBC:
        fp_req = fopen("../blockcipher/testvector/AES/AES192(CBC)KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/AES/AES192(CBC)KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_AES;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_AES256_CBC:
        fp_req = fopen("../blockcipher/testvector/AES/AES256(CBC)KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/AES/AES256(CBC)KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_AES;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    // case MG_CRYPTO_TEST_ID_KAT_AES128_CTR:
    //     fp_req = fopen("./blockcipher/testvector/AES/AES128(CTR)KAT.fax", "r");
    //     fp_rsp = fopen("./blockcipher/testvector/AES/AES128(CTR)KAT.txt", "w");
    //     alg_ID = MG_CRYPTO_ID_AES;
    //     mode_ID = MG_CRYPTO_MODE_CTR;
    //     break;
    // case MG_CRYPTO_TEST_ID_KAT_AES192_CTR:
    //     fp_req = fopen("./blockcipher/testvector/AES/AES192(CTR)KAT.fax", "r");
    //     fp_rsp = fopen("./blockcipher/testvector/AES/AES192(CTR)KAT.txt", "w");
    //     alg_ID = MG_CRYPTO_ID_AES;
    //     mode_ID = MG_CRYPTO_MODE_CTR;
    //     break;
    // case MG_CRYPTO_TEST_ID_KAT_AES256_CTR:
    //     fp_req = fopen("./blockcipher/testvector/AES/AES256(CTR)KAT.fax", "r");
    //     fp_rsp = fopen("./blockcipher/testvector/AES/AES256(CTR)KAT.txt", "w");
    //     alg_ID = MG_CRYPTO_ID_AES;
    //     mode_ID = MG_CRYPTO_MODE_CTR;
    //     break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA128_ECB:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-128_(ECB)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-128_(ECB)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA192_ECB:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-192_(ECB)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-192_(ECB)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA256_ECB:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-256_(ECB)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-256_(ECB)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA128_CBC:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-128_(CBC)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-128_(CBC)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA192_CBC:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-192_(CBC)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-192_(CBC)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA256_CBC:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-256_(CBC)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-256_(CBC)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA128_CTR:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-128_(CTR)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-128_(CTR)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_CTR;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA192_CTR:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-192_(CTR)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-192_(CTR)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_CTR;
        break;
    case MG_CRYPTO_TEST_ID_KAT_ARIA256_CTR:
        fp_req = fopen("../blockcipher/testvector/ARIA/ARIA-256_(CTR)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/ARIA/ARIA-256_(CTR)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_ARIA;
        mode_ID = MG_CRYPTO_MODE_CTR;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA128_ECB:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-128_(ECB)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-128_(ECB)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA192_ECB:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-192_(ECB)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-192_(ECB)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA256_ECB:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-256_(ECB)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-256_(ECB)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_ECB;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA128_CBC:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-128_(CBC)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-128_(CBC)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA192_CBC:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-192_(CBC)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-192_(CBC)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA256_CBC:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-256_(CBC)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-256_(CBC)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_CBC;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA128_CTR:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-128_(CTR)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-128_(CTR)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_CTR;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA192_CTR:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-192_(CTR)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-192_(CTR)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_CTR;
        break;
    case MG_CRYPTO_TEST_ID_KAT_LEA256_CTR:
        fp_req = fopen("../blockcipher/testvector/LEA/LEA-256_(CTR)_KAT.fax", "r");
        fp_rsp = fopen("../blockcipher/testvector/LEA/LEA-256_(CTR)_KAT.txt", "w");
        alg_ID = MG_CRYPTO_ID_LEA;
        mode_ID = MG_CRYPTO_MODE_CTR;
        break;
    default:
        fprintf(stderr, "Unhandled test ID: %d\n", test_ID); // 처리되지 않은 값에 대한 경고
        goto end;
        break;
    }

    // req, rsp 파일 오류 확인
    if(!fp_req) {
        perror("Failed to open fp_req");
        goto end;
    }
    if(!fp_rsp) {
        perror("Failed to open fp_rsp");
        goto end;
    }

    uint8_t key[32] = {0x00};     // 최대 키 길이 = 32-byte
    uint8_t iv[16] = {0x00};      // IV는 CBC, CTR에서만 사용
    uint8_t pt[160] = {0x00};     // 파일에서 읽은 정답 값
    uint8_t ct[160] = {0x00};     // 파일에서 읽은 정답 값
    uint8_t pt_res[160] = {0x00}; // test를 통해 생성될 값
    uint8_t ct_res[160] = {0x00}; // test를 통해 생성될 값
    uint8_t buf[500] = {0x00};

    uint32_t out_len; // 실제로 암호모듈에서 유효 데이터를 나타내는 out_len
    uint32_t pt_len;
    uint32_t ct_len; // req에서 읽은 ct_len
    uint32_t key_len;
    uint32_t iv_len; // req에서 읽은 IV 길이

    uint32_t pt_out_len; // rsp 파일에 write할 때 사용할 변수
    uint32_t ct_out_len; // rsp 파일에 write할 때 사용할 변수

    int32_t ret = 0; // fprintf 오류 리턴 값

    while(1) {
        out_len = 0;
        pt_len = 0;
        ct_len = 0;
        key_len = 0;
        iv_len = 0;
        pt_out_len = 0;
        ct_out_len = 0;
        memset(key, 0, sizeof(key));
        memset(iv, 0, sizeof(iv));
        memset(pt, 0, sizeof(pt));
        memset(ct, 0, sizeof(ct));
        memset(pt_res, 0, sizeof(pt_res));
        memset(ct_res, 0, sizeof(ct_res));

        // "KEY = " 제외한 값 buf에 저장
        ret = fscanf(fp_req, "%s %s %s", buf, buf, buf);
        if(feof(fp_req)) {
            break;
        }
        key_len = hex2bin(buf, key);

        // "IV = " 제외한 값 buf에 저장 (CBC, CTR은 iv를 읽어야함)
        if((mode_ID == MG_CRYPTO_MODE_CBC) || (mode_ID == MG_CRYPTO_MODE_CTR)) {
            ret = fscanf(fp_req, "%s %s %s", buf, buf, buf);
            iv_len = hex2bin(buf, iv);
        }

        // "PT = " 제외한 값 buf에 저장
        ret = fscanf(fp_req, "%s %s %s", buf, buf, buf);
        pt_len = hex2bin(buf, pt);

        // "CT = " 제외한 값 buf에 저장
        ret = fscanf(fp_req, "%s %s %s", buf, buf, buf);
        ct_len = hex2bin(buf, ct);

        // mg_cipher_param 구조체 초기화 및 값 설정
        // ECB는 IV 필요 없음
        mg_cipher_param param;
        memset(&param, 0, sizeof(mg_cipher_param));
        param.modeID = mode_ID;                 // 운용모드 설정
        param.paddingID = MG_CRYPTO_PADDING_NO; // 패딩 설정
        if(mode_ID == MG_CRYPTO_MODE_CBC || MG_CRYPTO_MODE_CTR) {
            memcpy(param.iv, iv, iv_len); // IV 값 설정
            param.iv_len = iv_len;        // IV 길이 설정
        }

        if(mode_ID == MG_CRYPTO_MODE_CTR) {
            // 앞서 설정을 혹시 바꾸더라도 (나중에 패딩 테스트용으로)
            // CTR은 패딩 x
            param.paddingID = MG_CRYPTO_PADDING_NO;
        }

        // 암호화 수행
        ret = MG_Crypto_Encrypt(key, key_len, alg_ID, &param, pt, pt_len, ct_res, &out_len);
        if(ret != 0) {
            fprintf(stderr, "Encryption failed\n");
            goto end;
        }
        ct_out_len = out_len;

        // 복호화 수행
        out_len = 0; // 유효 데이터 길이 초기화
        if(mode_ID == MG_CRYPTO_MODE_CTR) {
            // CTR은 암/복호화 때 Encrypt만 사용
            ret = MG_Crypto_Encrypt(key, key_len, alg_ID, &param, ct, ct_len, pt_res, &out_len);
            if(ret != 0) {
                fprintf(stderr, "Decryption failed\n");
                goto end;
            }
        } else {
            ret = MG_Crypto_Decrypt(key, key_len, alg_ID, &param, ct, ct_len, pt_res, &out_len);
            if(ret != 0) {
                fprintf(stderr, "Decryption failed\n");
                goto end;
            }
        }
        pt_out_len = out_len; // 복호화 후 유효 데이터 길이 저장 (복호화 된 평문 길이)

        ret = fprintf(fp_rsp, "KEY = ");
        for(uint32_t i = 0; i < key_len; i++) {
            ret = fprintf(fp_rsp, "%02X", key[i]);
        }
        ret = fprintf(fp_rsp, "\n");

        if((mode_ID == MG_CRYPTO_MODE_CBC) || (mode_ID == MG_CRYPTO_MODE_CTR)) {
            ret = fprintf(fp_rsp, "IV = ");
            for(uint32_t i = 0; i < iv_len; i++) {
                ret = fprintf(fp_rsp, "%02X", iv[i]);
            }
            ret = fprintf(fp_rsp, "\n");
        }

        ret = fprintf(fp_rsp, "PT = ");
        // 유효 데이터 길이가 맞는지 확인을 위해 pt_out_len으로 for문 동작
        for(uint32_t i = 0; i < pt_out_len; i++) {
            ret = fprintf(fp_rsp, "%02X", pt_res[i]);
        }
        ret = fprintf(fp_rsp, "\n");

        ret = fprintf(fp_rsp, "CT = ");
        // 유효 데이터 길이가 맞는지 확인을 위해 ct_out_len으로 for문 동작
        for(uint32_t i = 0; i < ct_out_len; i++) {
            ret = fprintf(fp_rsp, "%02X", ct_res[i]);
        }
        ret = fprintf(fp_rsp, "\n");
        ret = fprintf(fp_rsp, "\n");
    }

end:
    fclose(fp_req);
    fclose(fp_rsp);
}

int main() {

    // AES ECB 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES128_ECB);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES192_ECB);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES256_ECB);
    // ARIA ECB 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA128_ECB);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA192_ECB);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA256_ECB);
    // LEA ECB 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA128_ECB);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA192_ECB);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA256_ECB);
    // AES CBC 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES128_CBC);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES192_CBC);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES256_CBC);
    // ARIA CBC 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA128_CBC);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA192_CBC);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA256_CBC);
    // LEA CBC 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA128_CBC);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA192_CBC);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA256_CBC);
    // // AES CTR 테스트
    // // MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES128_CTR);
    // // MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES192_CTR);
    // // MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_AES256_CTR);
    // ARIA CTR 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA128_CTR);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA192_CTR);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_ARIA256_CTR);
    // LEA CTR 테스트
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA128_CTR);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA192_CTR);
    MG_Crypto_Test_KAT(MG_CRYPTO_TEST_ID_KAT_LEA256_CTR);

    return 0;
}
