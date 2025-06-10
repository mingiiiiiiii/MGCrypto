#include "mg_drbg.h"

int32_t CTR_DRBG_Test_PR_useDF(void) {
    printf("* AES128-CTR-DRBG test *\n");

    KISA_CTR_DRBG_STATE state;
    unsigned char buffer[64];
    int ret = 1;

    // 1) Instantiate (AES-128, DF=1, PredictionResistance=True)
    // const char* EntropyInput_hex = "d3454b257ecd83c3be96b8f5847be6eb";
    // const char* Nonce_hex = "b241f1295df4d999";
    // const char* PersStr_hex = "6e8d9b4dd8d17ec91111a4cb93ba4f25";
    unsigned char EntropyInput[16] = {
        0xd3, 0x45, 0x4b, 0x25, 0x7e, 0xcd, 0x83, 0xc3, 0xbe, 0x96, 0xb8, 0xf5, 0x84, 0x7b, 0xe6, 0xeb};
    unsigned char Nonce[8] = {
        0xb2, 0x41, 0xf1, 0x29, 0x5d, 0xf4, 0xd9, 0x99};
    unsigned char PersStr[16] = {
        0x6e, 0x8d, 0x9b, 0x4d, 0xd8, 0xd1, 0x7e, 0xc9, 0x11, 0x11, 0xa4, 0xcb, 0x93, 0xba, 0x4f, 0x25};

    ret = KISA_CTR_DRBG_Instantiate(&state, ALGO_AES128, EntropyInput, 16, Nonce, 8, PersStr, 16, USE_DERIVATION_FUNCTION);

    unsigned char key_expected_1[16] = {0xac, 0x03, 0x45, 0x31, 0xca, 0x77, 0xeb, 0x0e, 0xc3, 0x68, 0xa8, 0x63, 0x24, 0x2f, 0x24, 0x09};
    unsigned char v_expected_1[16] = {0x8c, 0x70, 0x56, 0x94, 0xc5, 0x3a, 0xbe, 0xa2, 0xe8, 0xc4, 0x2c, 0xb2, 0x3b, 0x5d, 0x53, 0x1f};
    // print_hex("Key ->", state.Key, 16);
    // print_hex("V   ->", state.V, 16);
    // Check if the key and V match expected values
    for(int i = 0; i < 16; i++) {
        if(state.Key[i] != key_expected_1[i] || state.V[i] != v_expected_1[i]) {
            printf("Initialization failed: Key or V does not match expected values.\n");
            return ret; // 1 -> fail!
        }
    }

    // 2) Generate (First Call) with PR: reseed first
    // const char* AddInput1_hex = "0bdeb888604db3a7b615b5bacbe42500";
    // const char* EntropyInputPR1_hex = "66d578535e2b4b41560298fe7fd9e240";
    unsigned char AddInput1[16] = {
        0x0b, 0xde, 0xb8, 0x88, 0x60, 0x4d, 0xb3, 0xa7, 0xb6, 0x15, 0xb5, 0xba, 0xcb, 0xe4, 0x25, 0x00};
    unsigned char EntropyInputPR1[16] = {
        0x66, 0xd5, 0x78, 0x53, 0x5e, 0x2b, 0x4b, 0x41, 0x56, 0x02, 0x98, 0xfe, 0x7f, 0xd9, 0xe2, 0x40};

    ret = KISA_CTR_DRBG_Reseed(&state, EntropyInputPR1, 16, AddInput1, 16);
    ret = KISA_CTR_DRBG_Generate(&state, buffer, 512, NULL, 0);

    unsigned char key_expected_2[16] = {0x05, 0xf1, 0xc8, 0x9d, 0xdd, 0xda, 0xb1, 0x45, 0x0c, 0xe5, 0xc9, 0x15, 0xad, 0x69, 0xe1, 0xdb};
    unsigned char v_expected_2[16] = {0xe6, 0xe8, 0x15, 0x2f, 0x34, 0xdc, 0x19, 0xb6, 0x7c, 0xfa, 0xf3, 0x86, 0xca, 0x96, 0x5c, 0x8a};
    // print_hex("Key ->", state.Key, 16);
    // print_hex("V   ->", state.V, 16);
    // Check if the key and V match expected values
    for(int i = 0; i < 16; i++) {
        if(state.Key[i] != key_expected_2[i] || state.V[i] != v_expected_2[i]) {
            printf("Generation failed: Key or V does not match expected values.\n");
            return ret; // 1 -> fail!
        }
    }

    // 3) Generate (Second Call) with PR: reseed first
    // const char* AddInput2_hex = "79f38dd58d835f1ae58955bbdb500cfc";
    // const char* EntropyInputPR2_hex = "1d97e89c603915207a6560520c4feb00";
    unsigned char AddInput2[16] = {
        0x79, 0xf3, 0x8d, 0xd5, 0x8d, 0x83, 0x5f, 0x1a, 0xe5, 0x89, 0x55, 0xbb, 0xdb, 0x50, 0x0c, 0xfc};
    unsigned char EntropyInputPR2[16] = {
        0x1d, 0x97, 0xe8, 0x9c, 0x60, 0x39, 0x15, 0x20, 0x7a, 0x65, 0x60, 0x52, 0x0c, 0x4f, 0xeb, 0x00};

    ret = KISA_CTR_DRBG_Reseed(&state, EntropyInputPR2, 16, AddInput2, 16);
    ret = KISA_CTR_DRBG_Generate(&state, buffer, 512, NULL, 0);
    // print_hex("Key ->", state.Key, 16);
    // print_hex("V   ->", state.V, 16);
    unsigned char key_expected_3[16] = {0xa6, 0x4a, 0x7e, 0x67, 0xf3, 0x0c, 0x53, 0x68, 0x81, 0x38, 0x5e, 0xbe, 0x7d, 0x0b, 0xe0, 0x6e};
    unsigned char v_expected_3[16] = {0x9f, 0xdb, 0xee, 0x32, 0xf2, 0xa8, 0x4b, 0x24, 0xb8, 0xd5, 0xce, 0x00, 0xce, 0x6f, 0xcd, 0xc7};
    // Check if the key and V match expected values
    for(int i = 0; i < 16; i++) {
        if(state.Key[i] != key_expected_3[i] || state.V[i] != v_expected_3[i]) {
            printf("Generation failed: Key or V does not match expected values.\n");
            return ret; // 1 -> fail!
        }
    }

    printf("AES128-CTR-DRBG (PR-yes DF-yes) Test Passed!\n");
    return ret - 1; // Return 0 for success, -1 for failure
}

int main() {
    int32_t ret = 0;

    ret = CTR_DRBG_Test_PR_useDF();

    return ret;
}