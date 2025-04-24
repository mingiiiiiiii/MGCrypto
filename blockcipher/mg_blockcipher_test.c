#include "mg_blockcipher.h"

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
}

/// @brief 16진수 문자열(hexlen 짝수) → byte 배열 변환
/// @return 성공하면 변환된 바이트 수, 실패하면 -1
uint32_t hex2bin(const uint8_t* hex,
                 uint8_t* out) {
    size_t hexlen = strlen((const int8_t*)hex);
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

void test_AES_ECB() {

    FILE* fp_req = fopen("./blockcipher/testvector/AES/AES128(ECB)KAT.fax", "r");
    if(!fp_req) {
        perror("Failed to open AES128(ECB)KAT.fax");
        exit(EXIT_FAILURE);
    }

    FILE* fp_rsp = fopen("./blockcipher/testvector/AES/AES128(ECB)KAT.txt", "w");
    if(!fp_rsp) {
        perror("Failed to open AES128(ECB)KAT.txt");
        fclose(fp_req); // 이전에 연 파일 닫기
        exit(EXIT_FAILURE);
    }

    uint8_t key[16] = {0x00};
    uint8_t pt[160] = {0x00};     // 파일에서 읽은 정답 값
    uint8_t ct[160] = {0x00};     // 파일에서 읽은 정답 값
    uint8_t pt_res[160] = {0x00}; // test를 통해 생성될 값
    uint8_t ct_res[160] = {0x00}; // test를 통해 생성될 값
    uint8_t iv[16] = {0x00};
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
        ret = MG_Crypto_Encrypt(key, key_len, MG_CRYPTO_ID_AES, &param, pt, pt_len, ct_res, &out_len);
        if(ret != 0) {
            fprintf(stderr, "Encryption failed\n");
            fclose(fp_req);
            fclose(fp_rsp);
            exit(EXIT_FAILURE);
        }
        ct_out_len = out_len;

        // 복호화 수행
        out_len = 0; // 유효 데이터 길이 초기화
        ret = MG_Crypto_Decrypt(key, key_len, MG_CRYPTO_ID_AES, &param, ct, ct_len, pt_res, &out_len);
        if(ret != 0) {
            fprintf(stderr, "Decryption failed\n");
            fclose(fp_req);
            fclose(fp_rsp);
            exit(EXIT_FAILURE);
        }
        pt_out_len = out_len;

        ret = fprintf(fp_rsp, "KEY = ");
        for(int i = 0; i < key_len; i++) {
            ret = fprintf(fp_rsp, "%02x", key[i]);
        }
        ret = fprintf(fp_rsp, "\n");

        ret = fprintf(fp_rsp, "PT = ");
        // 유효 데이터 길이가 맞는지 확인을 위해 pt_out_len으로 for문 동작
        for(int i = 0; i < pt_out_len; i++) {
            ret = fprintf(fp_rsp, "%02x", pt_res[i]);
        }
        ret = fprintf(fp_rsp, "\n");

        ret = fprintf(fp_rsp, "CT = ");
        // 유효 데이터 길이가 맞는지 확인을 위해 ct_out_len으로 for문 동작
        for(int i = 0; i < ct_out_len; i++) {
            ret = fprintf(fp_rsp, "%02x", ct_res[i]);
        }
        ret = fprintf(fp_rsp, "\n");
        ret = fprintf(fp_rsp, "\n");
    }

    fclose(fp_req);
    fclose(fp_rsp);
}

int main() {
    test_AES_ECB();
    return 0;
}