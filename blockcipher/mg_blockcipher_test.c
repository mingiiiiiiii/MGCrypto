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

void MG_Crypto_Test_ECB_KAT(uint32_t alg_ID,
                            enum MG_CRYPTO_TEST_ID test_ID) {
    FILE* fp_req = NULL;
    FILE* fp_rsp = NULL;

    switch(test_ID) {
    case MG_CRYPTO_TEST_ID_AES128:
        fp_req = fopen("./blockcipher/testvector/AES/AES128(ECB)KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open AES128(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/AES/AES128(ECB)KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open AES128(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_AES192:
        fp_req = fopen("./blockcipher/testvector/AES/AES192(ECB)KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open AES192(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/AES/AES192(ECB)KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open AES192(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_AES256:
        fp_req = fopen("./blockcipher/testvector/AES/AES256(ECB)KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open AES256(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/AES/AES256(ECB)KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open AES256(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_ARIA128:
        fp_req = fopen("./blockcipher/testvector/ARIA/ARIA-128_(ECB)_KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open ARIA-128_(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/ARIA/ARIA-128_(ECB)_KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open ARIA-128_(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_ARIA192:
        fp_req = fopen("./blockcipher/testvector/ARIA/ARIA-192_(ECB)_KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open ARIA-192_(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/ARIA/ARIA-192_(ECB)_KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open ARIA-192_(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_ARIA256:
        fp_req = fopen("./blockcipher/testvector/ARIA/ARIA-256_(ECB)_KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open ARIA-256_(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/ARIA/ARIA-256_(ECB)_KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open ARIA-256_(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_LEA128:
        fp_req = fopen("./blockcipher/testvector/LEA/LEA-128_(ECB)_KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open LEA-128_(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/LEA/LEA-128_(ECB)_KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open LEA-128_(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_LEA192:
        fp_req = fopen("./blockcipher/testvector/LEA/LEA-192_(ECB)_KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open LEA-192_(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/LEA/LEA-192_(ECB)_KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open LEA-192_(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    case MG_CRYPTO_TEST_ID_LEA256:
        fp_req = fopen("./blockcipher/testvector/LEA/LEA-256_(ECB)_KAT.fax", "r");
        if(!fp_req) {
            perror("Failed to open LEA-256_(ECB)KAT.fax");
            exit(EXIT_FAILURE);
        }

        fp_rsp = fopen("./blockcipher/testvector/LEA/LEA-256_(ECB)_KAT.txt", "w");
        if(!fp_rsp) {
            perror("Failed to open LEA-256_(ECB)KAT.txt");
            fclose(fp_req); // 이전에 연 파일 닫기
            exit(EXIT_FAILURE);
        }
        break;
    default:
        fprintf(stderr, "Unhandled test ID: %d\n", test_ID); // 처리되지 않은 값에 대한 경고
        break;
    }

    uint8_t key[32] = {0x00};     // 최대 키 길이 = 32-byte
    uint8_t pt[160] = {0x00};     // 파일에서 읽은 정답 값
    uint8_t ct[160] = {0x00};     // 파일에서 읽은 정답 값
    uint8_t pt_res[160] = {0x00}; // test를 통해 생성될 값
    uint8_t ct_res[160] = {0x00}; // test를 통해 생성될 값
    uint8_t buf[500] = {0x00};

    uint32_t out_len; // 실제로 암호모듈에서 유효 데이터를 나타내는 out_len
    uint32_t pt_len;
    uint32_t ct_len; // req에서 읽은 ct_len
    uint32_t key_len;

    uint32_t pt_out_len; // rsp 파일에 write할 때 사용할 변수
    uint32_t ct_out_len; // rsp 파일에 write할 때 사용할 변수

    int32_t ret = 0; // fprintf 오류 리턴 값

    while(1) {
        out_len = 0;
        pt_len = 0;
        ct_len = 0;
        key_len = 0;
        pt_out_len = 0;
        ct_out_len = 0;
        memset(key, 0, sizeof(key));
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
        param.modeID = MG_CRYPTO_MODE_ECB;
        param.paddingID = MG_CRYPTO_PADDING_NO;

        // 암호화 수행
        ret = MG_Crypto_Encrypt(key, key_len, alg_ID, &param, pt, pt_len, ct_res, &out_len);
        if(ret != 0) {
            fprintf(stderr, "Encryption failed\n");
            fclose(fp_req);
            fclose(fp_rsp);
            exit(EXIT_FAILURE);
        }
        ct_out_len = out_len;

        // 복호화 수행
        out_len = 0; // 유효 데이터 길이 초기화
        ret = MG_Crypto_Decrypt(key, key_len, alg_ID, &param, ct, ct_len, pt_res, &out_len);
        if(ret != 0) {
            fprintf(stderr, "Decryption failed\n");
            fclose(fp_req);
            fclose(fp_rsp);
            exit(EXIT_FAILURE);
        }
        pt_out_len = out_len;

        ret = fprintf(fp_rsp, "KEY = ");
        for(uint32_t i = 0; i < key_len; i++) {
            ret = fprintf(fp_rsp, "%02X", key[i]);
        }
        ret = fprintf(fp_rsp, "\n");

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

    fclose(fp_req);
    fclose(fp_rsp);
}

int main() {

    // AES ECB 테스트
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_AES, MG_CRYPTO_TEST_ID_AES128);
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_AES, MG_CRYPTO_TEST_ID_AES192);
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_AES, MG_CRYPTO_TEST_ID_AES256);

    // ARIA ECB 테스트
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_ARIA, MG_CRYPTO_TEST_ID_ARIA128);
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_ARIA, MG_CRYPTO_TEST_ID_ARIA192);
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_ARIA, MG_CRYPTO_TEST_ID_ARIA256);

    // LEA ECB 테스트
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_LEA, MG_CRYPTO_TEST_ID_LEA128);
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_LEA, MG_CRYPTO_TEST_ID_LEA192);
    MG_Crypto_Test_ECB_KAT(MG_CRYPTO_ID_LEA, MG_CRYPTO_TEST_ID_LEA256);

    return 0;
}