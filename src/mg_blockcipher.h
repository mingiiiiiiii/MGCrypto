#ifndef MG_BLOCKCIPHER_H
#define MG_BLOCKCIPHER_H

#include <stdint.h>
#include <mg_aes.h>
#include <mg_aria.h>
#include <mg_lea.h>


typedef struct {
	uint32_t blockSize;						//알고리즘의 블록 크기(byte수)
	uint32_t minkey_len;					//알고리즘의 최소 키 길이
	uint32_t maxkey_len;					//알고리즘의 최대 키 길이
}mg_cipher_info;

typedef struct {
	uint8_t iv[MG_CIPHER_MAX_IV_SIZE];		//maximum size of IV
	uint32_t iv_len;						//byte
	uint32_t modeID;						//무슨 운영모드
	uint32_t paddingID;						//무슨 패딩
}mg_cipher_param;

typedef struct {
	mg_cipher_info info;					//info 구조체
	mg_cipher_param param;					//param 구조체
	uint32_t algID;							//무슨 알고리즘 사용하는지 (LEA,ARIA,HIGHT)
	uint32_t dir;							//mg_CIPHER_ENCRYPT/DECRYPT
	union key_ctx_t {
		mg_aria_key	aria;				    //aria rk
		mg_lea_key	lea;				//lea rk
		mg_aes_key	aes;				//aes rk
	} key_ctx;
	uint8_t key[32];		//maximum size of key
	uint32_t key_len;		//key byte 수
	uint8_t remain[16];		//남은 byte 저장, maximum size of block
	uint32_t remain_len;	//남은 byte 수
}mg_cipher_ctx;

#endif // MG_BLOCKCIPHER_H