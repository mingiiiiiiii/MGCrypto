#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mg_drbg.h"

#define octet_to_int(os) (((unsigned int)(os)[0] << 24) ^ ((unsigned int)(os)[1] << 16) ^ ((unsigned int)(os)[2] << 8) ^ ((unsigned int)(os)[3]))
#define int_to_octet(os, i)                   \
    {                                         \
        (os)[0] = (unsigned char)((i) >> 24); \
        (os)[1] = (unsigned char)((i) >> 16); \
        (os)[2] = (unsigned char)((i) >> 8);  \
        (os)[3] = (unsigned char)(i);         \
    }

static void ctr_increase(unsigned char* counter) {

    unsigned int c_byte;

    c_byte = octet_to_int(counter + 12);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 12, c_byte);
    if(c_byte)
        return;

    c_byte = octet_to_int(counter + 8);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 8, c_byte);

    if(c_byte)
        return;

    c_byte = octet_to_int(counter + 4);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 4, c_byte);

    if(c_byte)
        return;

    c_byte = octet_to_int(counter + 0);
    c_byte++;
    c_byte &= 0xFFFFFFFF;
    int_to_octet(counter + 0, c_byte);
}

void KISA_BCC(char algo,
              unsigned char* K,
              unsigned char* data,
              int datalen,
              unsigned char* output_block,
              int outlen) {

    mg_aes_key aeskey;
    int n = datalen / outlen;
    int i, j;
    unsigned char inputblock[MAX_V_LEN_IN_BYTES];
    memset(inputblock, 0x00, MAX_V_LEN_IN_BYTES);
    memset(output_block, 0x00, outlen);

    switch(algo) {
    case ALGO_AES128:

        AES_set_encrypt_key(K, ALGO_AES128_KEYLEN_IN_BYTES * 8, &aeskey);

        for(j = 1; j <= n; j++) {
            for(i = 0; i < outlen; i++) {
                inputblock[i] = output_block[i] ^ data[i];
            }
            AES_encrypt(inputblock, output_block, &aeskey);
            data += AES_BLOCK_SIZE;
        }
        break;
    }

    memset(&aeskey, 0x00, sizeof(mg_aes_key));
    memset(inputblock, 0x00, MAX_V_LEN_IN_BYTES);
}

int KISA_Blockcipher_df(char algo,
                        unsigned char* input_string,
                        int input_str_len,
                        unsigned char* output,
                        int outlen) {
#define MAX_NUM_OF_BYTES_TO_RETURN 64
#define BLOCK_SIZE MAX_V_LEN_IN_BYTES
#define SIZE_INT 4

    int retcode = 0;
    int i = 0;
    int L = input_str_len;
    int N = outlen;
    unsigned char X[MAX_NUM_OF_BYTES_TO_RETURN];
    unsigned char K[ALGO_ARIA256_KEYLEN_IN_BYTES]; // Maximum length
    int KLen;
    unsigned char IV[BLOCK_SIZE];
    unsigned char block[BLOCK_SIZE];
    int j;
    unsigned char* S = NULL;
    int SLen = 0;
    unsigned char* temp = NULL;
    unsigned char* iv_s = NULL;
    int iv_s_len = 0;
    int templen = 0;
    unsigned char* ptr;
    mg_aes_key aeskey;

    if(outlen > MAX_NUM_OF_BYTES_TO_RETURN) {
        goto FREE_AND_EXIT;
    }

    // form S = L||N||input_string||0x80
    SLen = 8 + input_str_len + 1;
    if((SLen % AES_BLOCK_SIZE) != 0)
        SLen += (AES_BLOCK_SIZE - (SLen % AES_BLOCK_SIZE));

    S = (unsigned char*)malloc(SLen);
    memset(S, 0x00, SLen);
    int_to_octet(S, L);
    int_to_octet(S + SIZE_INT, N);
    memcpy(S + SIZE_INT + SIZE_INT, input_string, input_str_len);
    S[SIZE_INT + SIZE_INT + input_str_len] = 0x80;

    for(j = 0; j < ALGO_ARIA256_KEYLEN_IN_BYTES; j++)
        K[j] = j;

    KLen = (algo == ALGO_AES128) ? ALGO_AES128_KEYLEN_IN_BYTES : (algo == ALGO_ARIA128) ? ALGO_ARIA128_KEYLEN_IN_BYTES
                                                             : (algo == ALGO_ARIA192)   ? ALGO_ARIA192_KEYLEN_IN_BYTES
                                                                                        : ALGO_ARIA256_KEYLEN_IN_BYTES;

    templen = (KLen + outlen) + (BLOCK_SIZE - ((KLen + outlen) % BLOCK_SIZE));
    temp = (unsigned char*)malloc(templen);
    ptr = temp;
    iv_s_len = SLen + BLOCK_SIZE;
    iv_s = (unsigned char*)malloc(iv_s_len);
    i = 0;
    templen = 0;
    while(templen < KLen + outlen) {
        int_to_octet(IV, i);
        memset(IV + SIZE_INT, 0x00, BLOCK_SIZE - SIZE_INT);
        memcpy(iv_s, IV, BLOCK_SIZE);
        memcpy(iv_s + BLOCK_SIZE, S, SLen);

        KISA_BCC(algo, K, iv_s, iv_s_len, block, BLOCK_SIZE);
        memcpy(ptr, block, BLOCK_SIZE);
        ptr += BLOCK_SIZE;
        templen += BLOCK_SIZE;
        i++;
    }

    memcpy(K, temp, KLen);
    memcpy(X, temp + KLen, outlen);

    memset(temp, 0x00, templen);
    free(temp);

    temp = (unsigned char*)malloc((outlen) + (BLOCK_SIZE - ((outlen) % BLOCK_SIZE)));
    ptr = temp;
    templen = 0;

    switch(algo) {
    case ALGO_AES128:

        AES_set_encrypt_key(K, ALGO_AES128_KEYLEN_IN_BYTES * 8, &aeskey);
        while(templen < outlen) {
            AES_encrypt(X, X, &aeskey);

            memcpy(ptr, X, BLOCK_SIZE);
            ptr += BLOCK_SIZE;
            templen += BLOCK_SIZE;
        }
        break;
    }

    memcpy(output, temp, outlen);

    retcode = 1;
FREE_AND_EXIT:
    memset(&aeskey, 0x00, sizeof(mg_aes_key));

    if(S != NULL) {
        memset(S, 0x00, SLen);
        free(S);
    }
    if(temp != NULL) {
        memset(temp, 0x00, templen);
        free(temp);
    }
    if(iv_s != NULL) {
        memset(iv_s, 0x00, iv_s_len);
        free(iv_s);
    }
    memset(X, 0x00, MAX_NUM_OF_BYTES_TO_RETURN);
    memset(K, 0x00, ALGO_ARIA256_KEYLEN_IN_BYTES);
    memset(IV, 0x00, BLOCK_SIZE);
    memset(block, 0x00, BLOCK_SIZE);
    return retcode;
}

int MG_Crypto_CTR_DRBG_Update(unsigned char* provided_data,
                              MG_Crypto_CTR_DRBG_STATE* state) {
    unsigned char temp[MAX_SEEDLEN_IN_BYTES];
    int templen = 0;
    unsigned char* ptr;
    int i;
    // int ptrindex = 0;
    mg_aes_key aeskey;

    if(provided_data == NULL || state->seedlen <= 0) {
        return 0;
    }

    ptr = temp;

    switch(state->algo) {
    case ALGO_AES128:

        AES_set_encrypt_key(state->Key, ALGO_AES128_KEYLEN_IN_BYTES * 8, &aeskey);

        while(templen < state->seedlen) {
            ctr_increase(state->V);
            AES_encrypt(state->V, ptr, &aeskey);

            ptr += AES_BLOCK_SIZE;
            templen += AES_BLOCK_SIZE;
        }
        memset(&aeskey, 0x00, sizeof(mg_aes_key));
        break;
    }

    for(i = 0; i < state->seedlen; i++)
        temp[i] ^= provided_data[i];

    memcpy(state->Key, temp, state->Keylen);
    ptr = temp;
    memcpy(state->V, ptr + state->seedlen - (state->Vlen), state->Vlen);

    memset(temp, 0x00, state->seedlen);

    return 1;
}

int MG_Crypto_CTR_DRBG_Instantiate(MG_Crypto_CTR_DRBG_STATE* state,
                                   unsigned char algo,
                                   unsigned char* entropy_input,
                                   int entropylen,
                                   unsigned char* nonce,
                                   int noncelen,
                                   unsigned char* personalization_string,
                                   int stringlen,
                                   unsigned char derivation_function_flag) {

    unsigned char seed_material[MAX_SEEDLEN_IN_BYTES];
    unsigned char* seed_material_in = NULL;
    unsigned char* ptr = NULL;
    int seed_material_len = 0;
    int retcode = 0;

    if(entropy_input == NULL) {
        return 0;
    }

    if(derivation_function_flag == USE_DERIVATION_FUNCTION) {
        state->derivation_function_flag = USE_DERIVATION_FUNCTION;
    } else {
        state->derivation_function_flag = NON_DERIVATION_FUNCTION;
    }

    switch(algo) {

    case ALGO_AES128:
        if(derivation_function_flag == USE_DERIVATION_FUNCTION) {
            if(entropylen < ALGO_AES128_SECURITY_STRENGTH_IN_BYTES)
                return 0;
        } else {
            if(entropylen < ALGO_AES128_SEEDLEN_IN_BYTES)
                return 0;
        }

        if(nonce != NULL && noncelen < ALGO_AES128_SECURITY_STRENGTH_IN_BYTES / 2)
            return 0;

        state->seedlen = ALGO_AES128_SEEDLEN_IN_BYTES;
        state->Keylen = ALGO_AES128_KEYLEN_IN_BYTES;
        state->Vlen = ALGO_AES128_OUTLEN_IN_BYTES;
        break;

    default:
        return 0; // No Such Algorithm
    }

    state->algo = algo;

    if(state->derivation_function_flag == USE_DERIVATION_FUNCTION) {
        memset(seed_material, 0x00, MAX_SEEDLEN_IN_BYTES);
        seed_material_len = entropylen;
        if(nonce != NULL && noncelen > 0)
            seed_material_len += (noncelen);
        if(personalization_string != NULL && stringlen > 0)
            seed_material_len += (stringlen);

        ptr = seed_material_in = (unsigned char*)malloc(seed_material_len);

        memcpy(ptr, entropy_input, entropylen);
        if(nonce != NULL && noncelen > 0) {
            ptr += entropylen;
            memcpy(ptr, nonce, noncelen);
        }

        if(personalization_string != NULL && stringlen > 0) {
            ptr += noncelen;
            memcpy(ptr, personalization_string, stringlen);
        }

        if(!KISA_Blockcipher_df(algo, seed_material_in, seed_material_len, seed_material, state->seedlen)) {
            goto FREE_AND_EXIT;
        }
    } else {
        int loop = stringlen <= entropylen ? stringlen : entropylen;
        int i;

        if(loop > MAX_SEEDLEN_IN_BYTES)
            loop = MAX_SEEDLEN_IN_BYTES;
        // seed_material = entropy_input xor personalization_string
        memset(seed_material, 0x00, MAX_SEEDLEN_IN_BYTES);
        if(personalization_string == NULL || stringlen == 0)
            for(i = 0; i < entropylen; i++)
                seed_material[i] = entropy_input[i];
        else
            for(i = 0; i < loop; i++)
                seed_material[i] = entropy_input[i] ^ personalization_string[i];
    }

    memset(state->Key, 0x00, MAX_Key_LEN_IN_BYTES);
    memset(state->V, 0x00, MAX_V_LEN_IN_BYTES);

    if(!MG_Crypto_CTR_DRBG_Update(seed_material, state)) {
        goto FREE_AND_EXIT;
    }

    state->reseed_counter = 1;

    retcode = 1;
    state->initialized_flag = STATE_INITIALIZED_FLAG;

FREE_AND_EXIT:
    if(seed_material_in) {
        memset(seed_material_in, 0x00, seed_material_len);
        free(seed_material_in);
    }
    memset(seed_material, 0x00, MAX_SEEDLEN_IN_BYTES);
    return retcode;
}

int MG_Crypto_CTR_DRBG_Reseed(MG_Crypto_CTR_DRBG_STATE* state,
                              unsigned char* entropy_input,
                              int entropylen,
                              unsigned char* additional_input,
                              int addlen) {

    unsigned char seed_material[MAX_SEEDLEN_IN_BYTES];
    unsigned char* seed_material_in = NULL;
    unsigned char* ptr = NULL;
    int seed_material_len = 0;
    int retcode = 0;

    if(entropy_input == NULL) {
        return 0;
    }

    if(addlen > state->seedlen) {
        addlen = state->seedlen;
    }

    if((uint32_t)state->initialized_flag != STATE_INITIALIZED_FLAG) {
        return 0; // MG_Crypto_CTR_DRBG_Instantiate(...) required
    }

    switch(state->algo) {

    //--------------------------------------------------------------
    case ALGO_AES128:
        if(entropylen < ALGO_AES128_SECURITY_STRENGTH_IN_BYTES)
            return 0;
        break;

    default:
        return 0; // No Such Algorithm
    }

    if(state->derivation_function_flag == USE_DERIVATION_FUNCTION) {
        memset(seed_material, 0x00, MAX_SEEDLEN_IN_BYTES);
        seed_material_len = entropylen;
        if(addlen > 0)
            seed_material_len += (addlen);
        ptr = seed_material_in = (unsigned char*)malloc(seed_material_len);

        memcpy(ptr, entropy_input, entropylen);
        if(addlen > 0) {
            ptr += entropylen;
            memcpy(ptr, additional_input, addlen);
        }

        if(!KISA_Blockcipher_df(state->algo, seed_material_in, seed_material_len, seed_material, state->seedlen)) {
            goto FREE_AND_EXIT;
        }
    } else {
        int loop = addlen <= entropylen ? addlen : entropylen;
        int i;

        // seed_material = entropy_input xor additional input
        memset(seed_material, 0x00, MAX_SEEDLEN_IN_BYTES);

        if(additional_input == NULL || addlen == 0) {
            for(i = 0; i < entropylen; i++) {
                seed_material[i] = entropy_input[i];
            }
        } else {
            for(i = 0; i < loop; i++) {
                seed_material[i] = entropy_input[i] ^ additional_input[i];
            }
        }
    }

    if(!MG_Crypto_CTR_DRBG_Update(seed_material, state)) {
        goto FREE_AND_EXIT;
    }

    state->reseed_counter = 1;

    retcode = 1;

FREE_AND_EXIT:
    memset(seed_material_in, 0x00, seed_material_len);
    if(seed_material_in)
        free(seed_material_in);
    memset(seed_material, 0x00, MAX_SEEDLEN_IN_BYTES);
    return retcode;
}

int MG_Crypto_CTR_DRBG_Generate(MG_Crypto_CTR_DRBG_STATE* state,
                                unsigned char* output,
                                int requested_num_of_bits,
                                unsigned char* addtional_input,
                                int addlen) {
    mg_aes_key aeskey;

    unsigned char addtional_input_for_seed[MAX_SEEDLEN_IN_BYTES];
    int request_num_of_bytes;

    int retcode = 0;
    unsigned char* temp = NULL;
    unsigned char* ptr = NULL;
    int templen = 0;

    if(addlen > state->seedlen) {
        addlen = state->seedlen;
    }

    if(requested_num_of_bits <= 0) {
        return 0; // No length to generate
    } else {
        request_num_of_bytes = requested_num_of_bits / 8 + ((requested_num_of_bits % 8) != 0 ? 1 : 0);
    }

    if(state->reseed_counter > NUM_OF_REQUESTS_BETWEEN_RESEEDS) {
        return 0; // Reseed Required.
    }

    if(addtional_input != NULL && addlen > 0) {
        if(state->derivation_function_flag == USE_DERIVATION_FUNCTION) {
            if(!KISA_Blockcipher_df(state->algo, addtional_input, addlen, addtional_input_for_seed, state->seedlen)) {
                memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN_IN_BYTES);
                return 0;
            }

            if(!MG_Crypto_CTR_DRBG_Update(addtional_input_for_seed, state)) {
                memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN_IN_BYTES);
                return 0;
            }
        } else {
            memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN_IN_BYTES);
            memcpy(addtional_input_for_seed, addtional_input, addlen);

            if(!MG_Crypto_CTR_DRBG_Update(addtional_input_for_seed, state)) {
                memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN_IN_BYTES);
                return 0;
            }
        }
    } else {
        memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN_IN_BYTES);
    }

    templen = request_num_of_bytes + (MAX_V_LEN_IN_BYTES - (request_num_of_bytes % MAX_V_LEN_IN_BYTES));
    temp = (unsigned char*)malloc(templen);
    ptr = temp;
    templen = 0;

    switch(state->algo) {
    case ALGO_AES128:

        AES_set_encrypt_key(state->Key, ALGO_AES128_KEYLEN_IN_BYTES * 8, &aeskey);
        while(templen < request_num_of_bytes) {
            ctr_increase(state->V);
            AES_encrypt(state->V, ptr, &aeskey);
            ptr += ALGO_AES128_OUTLEN_IN_BYTES;
            templen += ALGO_AES128_OUTLEN_IN_BYTES;
        }
        memset(&aeskey, 0x00, sizeof(mg_aes_key));
        break;
    }

    memcpy(output, temp, request_num_of_bytes);
    if(requested_num_of_bits % 8 != 0)
        output[request_num_of_bytes - 1] = temp[request_num_of_bytes - 1] & (0x000000FF & (0xFF << (8 - (requested_num_of_bits % 8))));

    if(!MG_Crypto_CTR_DRBG_Update(addtional_input_for_seed, state)) {
        goto FREE_AND_EXIT;
    }

    (state->reseed_counter)++;

    retcode = 1;
FREE_AND_EXIT:
    memset(temp, 0x00, templen);
    if(temp)
        free(temp);
    memset(addtional_input_for_seed, 0x00, MAX_SEEDLEN_IN_BYTES);
    return retcode;
}
