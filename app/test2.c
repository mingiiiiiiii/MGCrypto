#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mg_api.h"
#include "mg_crypto.h"

// Helper to generate a random IV (for demonstration purposes, use a strong PRNG in production)
void generate_random_bytes(unsigned char *buf, size_t len) {
	// In a real application, use a cryptographically secure random number generator (CSPRNG)
	// such as OpenSSL's RAND_bytes(). For this example, we'll just fill with a simple pattern.
	for (size_t i = 0; i < len; ++i) {
		buf[i] = (unsigned char)(rand() % 256);
	}
}

int main() {
	const unsigned char key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
																 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};	 // 16 bytes for AES-128
	const size_t key_len = 16;																											 // Exclude null terminator

	const unsigned char iv[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
																0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};	// GCM recommended IV length is 12 bytes

	const unsigned char aad[20] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
																 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
	const size_t aad_len = 20;

	unsigned char encrypted_tag[16] = {0x00};	 // GCM tag is typically 16 bytes
	unsigned char decrypted_tag[16] = {0x00};

	FILE *input_file = NULL;
	FILE *encrypted_file = NULL;
	FILE *decrypted_file = NULL;

	const char *original_filename = "input_image.png";
	const char *encrypted_filename = "encrypted_image.bin";	 // Changed name for encrypted file
	const char *decrypted_filename = "decrypted_image.png";	 // Changed name for decrypted file

	printf("--- Encryption Test ---\n");

	// Open files for encryption
	input_file = fopen(original_filename, "rb");
	encrypted_file = fopen(encrypted_filename, "wb");
	if (!input_file || !encrypted_file) {
		perror("Failed to open files for encryption");
		// Clean up partially created dummy file if any
		remove(original_filename);
		return 1;
	}

	// Encrypt the file
	int encrypt_result = mg_gcm_encrypt_file(key, key_len, iv, sizeof(iv), aad, aad_len, encrypted_tag,
																					 sizeof(encrypted_tag), input_file, encrypted_file);
	if (encrypt_result == MG_GCM_SUCCESS) {
		printf("File encrypted successfully!\n");
		printf("Generated Tag: ");
		for (size_t i = 0; i < sizeof(encrypted_tag); ++i) {
			printf("%02x", encrypted_tag[i]);
		}
		printf("\n");
	} else {
		printf("File encryption failed with error code: %d\n", encrypt_result);
		goto end;
	}

	fclose(input_file);
	fclose(encrypted_file);

	printf("\n--- Decryption Test ---\n");

	// Open files for decryption
	encrypted_file = fopen(encrypted_filename, "rb");
	decrypted_file = fopen(decrypted_filename, "wb");
	if (!encrypted_file || !decrypted_file) {
		perror("Failed to open files for decryption");
		goto end;
	}

	// Decrypt the file
	int decrypt_result = mg_gcm_decrypt_file(key, key_len, iv, sizeof(iv), aad, aad_len, encrypted_tag,
																					 sizeof(encrypted_tag),	 // Use the same tag
																					 encrypted_file, decrypted_file);
	if (decrypt_result == MG_GCM_SUCCESS) {
		printf("File decrypted successfully! (Tag verified)\n");
	} else {
		printf("File decryption failed with error code: %d\n", decrypt_result);
		if (decrypt_result == MG_GCM_ERROR_TAG_MISMATCH) {
			printf("Authentication tag mismatch. Data might be tampered or key/IV is incorrect.\n");
		}
		goto end;
	}

	fclose(encrypted_file);
	fclose(decrypted_file);

	printf("\nComparison of original and decrypted files:\n");
	// You can add code here to compare input_image.png and decrypted_image.png
	// to verify they are identical.
	// For a simple binary comparison:
	input_file = fopen(original_filename, "rb");
	decrypted_file = fopen(decrypted_filename, "rb");
	if (input_file && decrypted_file) {
		fseek(input_file, 0, SEEK_END);
		long original_size = ftell(input_file);
		fseek(input_file, 0, SEEK_SET);

		fseek(decrypted_file, 0, SEEK_END);
		long decrypted_size = ftell(decrypted_file);
		fseek(decrypted_file, 0, SEEK_SET);

		if (original_size != decrypted_size) {
			printf("Sizes differ: Original = %ld bytes, Decrypted = %ld bytes\n", original_size, decrypted_size);
		} else {
			unsigned char orig_byte, dec_byte;
			int mismatch = 0;
			for (long i = 0; i < original_size; ++i) {
				orig_byte = fgetc(input_file);
				dec_byte = fgetc(decrypted_file);
				if (orig_byte != dec_byte) {
					printf("Files differ at byte %ld: Original = %02x, Decrypted = %02x\n", i, orig_byte, dec_byte);
					mismatch = 1;
					break;
				}
			}
			if (!mismatch) {
				printf("Original and decrypted files are identical.\n");
			}
		}
	} else {
		perror("Failed to open files for comparison");
	}
	if (input_file) fclose(input_file);
	if (decrypted_file) fclose(decrypted_file);

end:
	// Clean up files
	// remove(original_filename);
	// remove(encrypted_filename);
	// remove(decrypted_filename);

	return 0;
}