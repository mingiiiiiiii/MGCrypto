#include <stdint.h>

// "mg_blockcipher.h"
typedef struct {
    uint8_t iv[16];     // maximum size of IV
    uint32_t iv_len;    // IV len (byte)
    uint32_t modeID;    // 무슨 운영모드
    uint32_t paddingID; // 무슨 패딩
} mg_cipher_param;

/**
 * @brief 1회성 복호화 helper: init→update→final을 한 번에 호출
 *
 * @param key           : 비밀키 버퍼
 * @param key_len       : 비밀키 길이 (byte)
 * @param alg_ID        : 알고리즘 ID (MG_CRYPTO_ID_…)
 * @param param         : 암호 파라미터 (IV, 모드, 패딩 등)
 * @param in            : 암호문 버퍼
 * @param in_len        : 암호문 길이 (byte)
 * @param out           : 복호화된 평문 출력 버퍼
 * @param out_len       : [out] 실제 복호화되어 출력된 평문 길이 (byte)
 * @return MG_SUCCESS (0) 이외는 실패 코드
 */
int32_t MG_Crypto_Decrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint64_t in_len,
                          uint8_t* out,
                          uint32_t* out_len);

/**
 * @brief 1회성 암호화 helper: init→update→final을 한 번에 호출
 *
 * @param key           : 비밀키 버퍼
 * @param key_len       : 비밀키 길이 (byte)
 * @param alg_ID        : 알고리즘 ID (MG_CRYPTO_ID_…)
 * @param dir           : MG_Crypto_ENCRYPT
 * @param param         : 암호 파라미터 (IV, 모드, 패딩 등)
 * @param in            : 평문 버퍼
 * @param in_len        : 평문 길이 (byte)
 * @param out           : 암호문 출력 버퍼
 * @param out_len       : [out] 실제 출력된 암호문 길이 (byte)
 * @return MG_SUCCESS (0) 이외는 실패 코드
 */
int32_t MG_Crypto_Encrypt(const uint8_t* key,
                          uint32_t key_len,
                          uint32_t alg_ID,
                          const mg_cipher_param* param,
                          const uint8_t* in,
                          uint64_t in_len,
                          uint8_t* out,
                          uint32_t* out_len);

// mg_gcm.h
/**
 * @brief AES-GCM 암호화 작업을 초기화합니다.
 *
 * @param key 암호화에 사용할 AES 키 (16, 24 또는 32 바이트)
 * @param key_len 키의 길이 (16, 24, 32)
 * @param iv GCM IV (Nonce). 12바이트를 권장하며, 각 암호화 세션마다 고유해야 합니다.
 * @param iv_len IV의 길이
 * @param aad 추가 인증 데이터 (선택 사항). NULL인 경우 사용되지 않습니다.
 * @param aad_len AAD의 길이. aad가 NULL이 아닌 경우 0보다 커야 합니다.
 * @param output_tag 암호화 후 생성될 GCM 인증 태그를 저장할 버퍼 (최소 16바이트).
 * 이 태그는 복호화 시 사용됩니다.
 * @param output_tag_len output_tag 버퍼의 크기. 최소 16바이트를 권장합니다.
 * @param input_file 암호화할 원본 파일의 파일 포인터
 * @param output_file 암호화된 데이터를 쓸 파일의 파일 포인터
 * @return 성공 시 MG_GCM_SUCCESS(0), 실패 시 음수 오류 코드
 */
int mg_gcm_encrypt_file(const unsigned char* key,
                        size_t key_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        unsigned char* output_tag,
                        size_t output_tag_len,
                        FILE* input_file,
                        FILE* output_file);

/**
 * @brief AES-GCM 복호화 작업을 초기화합니다.
 *
 * @param key 복호화에 사용할 AES 키 (16, 24 또는 32 바이트)
 * @param key_len 키의 길이 (16, 24, 32)
 * @param iv GCM IV (Nonce). 암호화에 사용된 IV와 동일해야 합니다.
 * @param iv_len IV의 길이
 * @param aad 추가 인증 데이터 (선택 사항). 암호화 시 사용된 AAD와 동일해야 합니다.
 * NULL인 경우 사용되지 않습니다.
 * @param aad_len AAD의 길이. aad가 NULL이 아닌 경우 0보다 커야 합니다.
 * @param input_tag GCM 인증 태그. 암호화 시 생성된 태그와 동일해야 합니다.
 * @param input_tag_len input_tag 버퍼의 크기. 암호화 시 사용된 태그 길이와 동일해야 합니다.
 * @param input_file 복호화할 암호화된 파일의 파일 포인터
 * @param output_file 복호화된 데이터를 쓸 파일의 파일 포인터
 * @return 성공 시 MG_GCM_SUCCESS(0), 실패 시 음수 오류 코드 (태그 불일치 포함)
 */
int mg_gcm_decrypt_file(const unsigned char* key,
                        size_t key_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        const unsigned char* input_tag,
                        size_t input_tag_len,
                        FILE* input_file,
                        FILE* output_file);

// "mg_hash.h"
/**
 * @brief 암호학적 HASH 연산 수행
 *
 * @param in 입력 데이터 버퍼
 * @param in_len 입력 데이터 길이 (byte)
 * @param out 해시 결과를 저장할 출력 버퍼
 * @param out_len 출력 버퍼의 크기 (byte)
 * @param hash_id 사용할 해시 알고리즘의 ID (예: SHA-256, SHA-512 등)
 * @return MG_SUCCESS (0) 이외는 실패 코드
 */
int32_t MG_Crypto_Hash(const uint8_t* in,
                       const uint64_t in_len,
                       uint8_t* out,
                       const uint32_t out_len,
                       const uint32_t hash_id);

// "mg_hmac.h"
/**
 * @brief HMAC (Hash-based Message Authentication Code) 생성
 *
 * @param key HMAC 키 버퍼
 * @param keylen HMAC 키 길이 (byte)
 * @param msg 입력 메시지 버퍼
 * @param msglen 입력 메시지 길이 (byte)
 * @param hmac 출력 HMAC 결과를 저장할 버퍼
 * @param hmac_id 사용할 HMAC 알고리즘의 ID (예: SHA-256, SHA-512 등)
 * @return MG_SUCCESS (0) 이외는 실패 코드
 */
int32_t MG_Crypto_HMAC(const uint8_t* key,
                       const uint32_t keylen,
                       const uint8_t* msg,
                       const uint32_t msglen,
                       uint8_t* hmac,
                       const uint32_t hmac_id);

// "mg_kdf.h"
/**
 * @brief MG_Crypto_KDF function (Key Derivation Function)
 * @param password Pointer to the password used for key derivation
 * @param passwordLen Length of the password in bytes
 * @param salt Pointer to the salt used for key derivation
 * @param saltLen Length of the salt in bytes
 * @param iter Number of iterations for the KDF
 * @param key Pointer to the output buffer where the derived key will be stored
 * @param keyLen Length of the derived key in bytes
 * @param kdf_id Identifier for the KDF algorithm to be used (MG_KDF_ID_*)
 * @return int32_t Returns MG_SUCCESS on success, or an error code on failure
 */
int32_t MG_Crypto_KDF(unsigned char* password,
                      int passwordLen,
                      unsigned char* salt,
                      int saltLen,
                      int iter,
                      unsigned char* key,
                      int keyLen,
                      const uint32_t kdf_id);

/*!
 * \brief
 * CTR DRBG 구현을 위한 내부 변수 구조체 (STATE)
 */
typedef struct ctr_drbg_state {
    unsigned char algo; /*!< ALGO_SEED / ALGO_ARIA128 / ALGO_ARIA192 / ALGO_ARIA256 */
    unsigned char V[MAX_V_LEN_IN_BYTES];
    int Vlen;
    unsigned char Key[MAX_Key_LEN_IN_BYTES];
    int Keylen;
    int seedlen;
    uint64_t reseed_counter;
    int security_strength;
    int initialized_flag;                   // If initialized_flag = STATE_INITIALIZED_FLAG, state is already initialized.
    unsigned char derivation_function_flag; // 0x00 : non-df ,  0xFF : use df
} MG_Crypto_CTR_DRBG_STATE;

/*!
 * @brief CTR DRBG 초기화 함수. 랜덤 생성을 위해서는 반드시 초기화가 필요
 * @param state 정보를 담고 있는 MG_Crypto_CTR_DRBG_STATE 구조체
 * @param algo 내부에서 사용될 대칭키 암호를 지정 (ALGO_SEED / ALGO_ARIA128 / ALGO_ARIA192 / ALGO_ARIA256 중 택일)
 * @param entropy_input
 * 랜덤 엔진 초기화를 위한 엔트로피 정보 입력
 * (길이는 사용하는 대칭키 암호의 ALGO_XXX_SECURITY_STRENGTH_IN_BYTES 이상을 입력해야함)
 * (i.e. SEED : 16 bytes / ARIA128 : 16 bytes / ARIA192 : 24 bytes / ARIA256 : 32 bytes 이상)
 * (Derivation Function을 사용하지 않을 경우에는 ALGO_xxx_SEEDLEN_IN_BYTES 이상을 입력해야 함)
 * @param entropylen 입력하는 엔트로피의 길이 (bytes 단위)
 * @param nonce
 * 랜덤 엔진 초기화를 위한 Nonce 입력
 * (입력 블럭암호의 security strength 절반 이상을 입력해야 함)
 * @param noncelen 입력하는 엔트로피의 길이 (bytes 단위)
 * @param personalization_string 사용자 지정 스트링 입력(옵션). 입력하지 않을 경우 NULL
 * @param stringlen 사용자 지정 스트링의 길이. NULL일 경우 길이를 0으로 입력
 * @param derivation_function_flag
 * 입력하는 엔트로피 정보가 Full Entropy일 경우 : NON_DERIVATION_FUNCTION /
 * 입력하는 엔트로피 정보가 Full Entropy가 아닐 경우 : USE_DERIVATION_FUNCTION
 * @returns 초기화 성공 (1) / 실패 (0)
 */
int MG_Crypto_CTR_DRBG_Instantiate(MG_Crypto_CTR_DRBG_STATE* state,
                                   unsigned char algo,
                                   unsigned char* entropy_input,
                                   int entropylen,
                                   unsigned char* nonce,
                                   int noncelen,
                                   unsigned char* personalization_string,
                                   int stringlen,
                                   unsigned char derivation_function_flag);

/*!
 * @brief CTR DRBG 랜덤 생성 함수. 반드시 MG_Crypto_CTR_DRBG_Instantiate 구동 이후에 실행 가능
 * @param state 정보를 담고 있는 MG_Crypto_CTR_DRBG_STATE 구조체
 * @param output 생성될 랜덤이 입력되는 버퍼
 * @param request_num_of_bits 생성될 랜덤의 길이 (bits) 단위
 * @param additional_input 부가적인 랜덤시드 입력(옵션). 입력하지 않을 경우 NULL
 * @param addlen 사용자 지정 스트링의 길이. NULL일 경우 길이를 0으로 입력
 * @returns 성공 (1) / 실패 (0)
 */
int MG_Crypto_CTR_DRBG_Generate(MG_Crypto_CTR_DRBG_STATE* state,
                                unsigned char* output,
                                int request_num_of_bits,
                                unsigned char* addtional_input,
                                int addlen);

/*!
 * @brief CTR DRBG 재 초기화 함수(필요시). MG_Crypto_CTR_DRBG_Instantiate를 사전에 구동시킨 이후에 사용 가능
 * @param state 정보를 담고 있는 MG_Crypto_CTR_DRBG_STATE 구조체
 * @param entropy_input
 * 랜덤 엔진 초기화를 위한 엔트로피 정보 입력
 * (길이는 사용하는 대칭키 암호의 ALGO_XXX_SECURITY_STRENGTH_IN_BYTES 이상을 입력해야함)
 * (i.e. SEED : 16 bytes / ARIA128 : 16 bytes / ARIA192 : 24 bytes / ARIA256 : 32 bytes 이상)
 * (Derivation Function을 사용하지 않을 경우에는 ALGO_xxx_SEEDLEN_IN_BYTES 이상을 입력해야 함)
 * @param entropylen 입력하는 엔트로피의 길이 (bytes 단위)
 * @param additional_input 부가적인 랜덤시드 입력(옵션). 입력하지 않을 경우 NULL
 * @param addlen 사용자 지정 스트링의 길이. NULL일 경우 길이를 0으로 입력
 * @returns 성공 (1) / 실패 (0)
 */
int MG_Crypto_CTR_DRBG_Reseed(MG_Crypto_CTR_DRBG_STATE* state,
                              unsigned char* entropy_input,
                              int entropylen,
                              unsigned char* additional_input,
                              int addlen);
