#ifndef MG_ARIA_H
#define MG_ARIA_H

void DL(const unsigned char* i,
        unsigned char* o);

void RotXOR(const unsigned char* s,
            int n,
            unsigned char* t);

typedef struct {
    uint32_t rk[272]; // 16 * (R + 1), MAX of R = 16
    // uint32_t key_len; // 16, 24, 32 bytes
    uint32_t round; // 12, 14, 16
} mg_aria_key;

int EncKeySetup(const unsigned char* w0,
                unsigned char* e,
                int keyBits);

int DecKeySetup(const unsigned char* w0,
                unsigned char* d,
                int keyBits);

void Crypt(const unsigned char* p,
           int R,
           const unsigned char* e,
           unsigned char* c);

void printBlockOfLength(unsigned char* b,
                        int len);

void printBlock(unsigned char* b);

#endif // MG_ARIA_H