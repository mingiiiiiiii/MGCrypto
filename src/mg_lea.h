#ifndef MG_LEA_H
#define MG_LEA_H

#define ROR(W, i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W, i) (((W) << (i)) | ((W) >> (32 - (i))))

#define ctow(w, c) (*(w) = *((unsigned int*)(c)))
#define wtoc(c, w) (*((unsigned int*)(c)) = *(w))
#define loadU32(v) (v)

void lea_encrypt(unsigned char* ct,
                 const unsigned char* pt,
                 const LEA_KEY* key);
void lea_decrypt(unsigned char* pt,
                 const unsigned char* ct,
                 const LEA_KEY* key);

#endif // MG_LEA_H