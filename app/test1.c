#include <stdio.h>

#include "mg_api.h"
#include "mg_crypto.h"
#include "mg_gcm.h"

int main() {
	uint8_t key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
	uint32_t key_len = sizeof(key);
	uint8_t in[16] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
	uint64_t in_len = sizeof(in);
	uint32_t alg_ID = MG_CRYPTO_ID_AES;	 // Example algorithm ID
	uint8_t out[16] = {0};
	uint32_t out_len = 0;

	mg_cipher_param param = {0};
	param.modeID = MG_CRYPTO_MODE_ECB;			 // Example mode ID
	param.paddingID = MG_CRYPTO_PADDING_NO;	 // Example padding ID

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