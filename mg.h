#ifndef _MG_H_
#define _MG_H_

#include <stdint.h>

#define CSE_SUCCESS							0
#define CSE_FAIL							-1
#define CSE_NOT_INIT						-2

// CIPHER
#define CSE_CIPHER_ENCRYPT_DIR				0
#define CSE_CIPHER_DECRYPT_DIR				1

#define CSE_CIPHER_MODE_ECB					0
#define CSE_CIPHER_MODE_CBC					1
#define CSE_CIPHER_MODE_CTR					2
#define CSE_CIPHER_MODE_GCM					3

#define CSE_CIPHER_ID_ARIA					0
#define CSE_CIPHER_ID_LEA					1
#define CSE_CIPHER_ID_HIGHT					2
#define CSE_CIPHER_ID_AES					9

#define CSE_CIPHER_MAX_IV_SIZE				16

#define CSE_CIPHER_PADDING_NO				0		//패딩 없음
#define CSE_CIPHER_PADDING_ZERO				1		//패딩 0으로
#define CSE_CIPHER_PADDING_ONEZERO			2		//패딩 최상단 1 이후 0
#define CSE_CIPHER_PADDING_PKCS				3		//패딩 필요한 블록 수 만큼, 3 블록 필요한 경우 03 03 03 03 패딩, 패딩이 필요없는 경우 패딩 방법을 표시하기 위해 10 10 10 10 10... 추가

#endif // _MG_H_