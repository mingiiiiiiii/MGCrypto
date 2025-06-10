# MGCrypto

## Build
```bash
# in ~/MGCrypto
$ make
$ ./blockcipher_test
```

## 테스트 벡터 검증
`blockcipher/testvector`에 `*.txt` 파일이 생성됨 \
`*.fax` 파일과 비교 수행

## 라이브러리 생성
`/lib`에 `libmgcrypto.so`가 생성됨 \
`/include/mg_api.h`에 선언된 함수들 사용 가능

## 지원하는 알고리즘
### Block Cipher
- AES (ECB, CBC, CTR, GCM)
- LEA (ECB, CBC, CTR)
- ARIA (ECB, CBC, CTR)

### Hash
- SHA2-256
- SHA2-384
- SHA2-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHAKE128
- SHAKE256
- LSH-512

### Message Authentication Code
- HMAC-SHA2-256
- HMAC-SHA2-384
- HMAC-SHA2-512

### KDF
- PBKDF2-HMAC-SHA256

### DRBG
- AES128-CTR-DRBG

<br>

<!-- ### Public,,,


### RSA

### Key Exchange

### Signature -->

# 라이브러리 사용법
## MGCrypto API
더 많은 정보는 `/include/mg_api.h` 함수 선언 및 주석 참고
```C
int32_t MG_Crypto_Decrypt();
int32_t MG_Crypto_Encrypt();
int32_t MG_GCM_Encrypt_File();
int32_t MG_GCM_Decrypt_File();
int32_t MG_Crypto_Hash();
int32_t MG_Crypto_HMAC();
int32_t MG_Crypto_KDF();
int32_t MG_Crypto_CTR_DRBG_Instantiate();
int32_t MG_Crypto_CTR_DRBG_Generate();
int32_t MG_Crypto_CTR_DRBG_Reseed();
```
## MGCrypto Library Example
`lib/libmgcrypto.so`, `inlcude/mg_api.h`, `include/mg_crypto.h`를 `app` 디렉토리에 복사\
`app` 디렉토리 안에서 테스트 수행\
필요 파일들이 모인 `app` 디렉토리를 외부로 이동시켜도 무방함
```plaintext
app/
├── input_image.png
├── libmgcrypto.so
├── mg_api.h
├── mg_crypto.h
├── randombytes.c
├── randombytes.h
├── test1
├── test1.c
├── test2
└── test2.c
```
### Test1 - AES128 암호화
```C
// test1.c
#include <stdio.h>

#include "mg_api.h"
#include "mg_crypto.h"
#include "mg_gcm.h"

int main() {
	uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
	uint32_t key_len = sizeof(key);
	uint8_t in[16] = {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
	uint64_t in_len = sizeof(in);
	uint32_t alg_ID = MG_CRYPTO_ID_AES;     // Example algorithm ID
	uint8_t out[16] = {0};
	uint32_t out_len = 0;

	mg_cipher_param param = {0};
	param.modeID = MG_CRYPTO_MODE_ECB;		// Example mode ID
	param.paddingID = MG_CRYPTO_PADDING_NO;	// Example padding ID

	int32_t result = 0;

	result = MG_Crypto_Encrypt(key, key_len, alg_ID, &param, in, in_len, out, &out_len);
	if (result == MG_SUCCESS) {
		printf("Encryption successful. Output length: %u\n", out_len);
		for (uint32_t i = 0; i < out_len; i++) {
			printf("%02X ", out[i]);
		}
		printf("\n");
	} else {
		printf("Encryption failed with error code: %d\n", result);
	}

	// ans = 3A D7 7B B4 0D 7A 36 60 A8 9E CA F3 24 66 EF 97

	return result;
}
```
```bash
# execute test1
$ gcc -I. test1.c -L. -lmgcrypto -o test1
$ LD_LIBRARY_PATH=. ./test1
```
### Test2 - KDF/DRBG/BlockCipher를 사용한 대용량 파일 암/복호화
`GCM` 운영모드를 통해 암호화와 인증 기능 제공\
`DRBG`를 통한 랜덤한 IV 생성\
`KDF`를 통한 개인 키 생성\
💡**암/복호화를 위한 파일이 존재해야함 (name = "input_image.png")**
```bash
# execute test2
$ gcc -I. test2.c randombytes.c -L. -lmgcrypto -o test2
$ LD_LIBRARY_PATH=. ./test2
```