#include "mg_gcm.h"

#define PACK(s) ((size_t)(s) << (sizeof(size_t) * 8 - 16))
#define REDUCE1BIT(V)                                                       \
    do {                                                                    \
        if(sizeof(size_t) == 8) {                                           \
            uint64_t T = (uint64_t)(0xe100000000000000) & (0 - (V.lo & 1)); \
            V.lo = (V.hi << 63) | (V.lo >> 1);                              \
            V.hi = (V.hi >> 1) ^ T;                                         \
        } else {                                                            \
            uint32_t T = 0xe1000000U & (0 - (uint32_t)(V.lo & 1));          \
            V.lo = (V.hi << 63) | (V.lo >> 1);                              \
            V.hi = (V.hi >> 1) ^ ((uint64_t)T << 32);                       \
        }                                                                   \
    } while(0)

/*-
 *
 * NOTE: TABLE_BITS and all non-4bit implementations have been removed in 3.1.
 *
 * Even though permitted values for TABLE_BITS are 8, 4 and 1, it should
 * never be set to 8. 8 is effectively reserved for testing purposes.
 * TABLE_BITS>1 are lookup-table-driven implementations referred to as
 * "Shoup's" in GCM specification. In other words OpenSSL does not cover
 * whole spectrum of possible table driven implementations. Why? In
 * non-"Shoup's" case memory access pattern is segmented in such manner,
 * that it's trivial to see that cache timing information can reveal
 * fair portion of intermediate hash value. Given that ciphertext is
 * always available to attacker, it's possible for him to attempt to
 * deduce secret parameter H and if successful, tamper with messages
 * [which is nothing but trivial in CTR mode]. In "Shoup's" case it's
 * not as trivial, but there is no reason to believe that it's resistant
 * to cache-timing attack. And the thing about "8-bit" implementation is
 * that it consumes 16 (sixteen) times more memory, 4KB per individual
 * key + 1KB shared. Well, on pros side it should be twice as fast as
 * "4-bit" version. And for gcc-generated x86[_64] code, "8-bit" version
 * was observed to run ~75% faster, closer to 100% for commercial
 * compilers... Yet "4-bit" procedure is preferred, because it's
 * believed to provide better security-performance balance and adequate
 * all-round performance. "All-round" refers to things like:
 *
 * - shorter setup time effectively improves overall timing for
 *   handling short messages;
 * - larger table allocation can become unbearable because of VM
 *   subsystem penalties (for example on Windows large enough free
 *   results in VM working set trimming, meaning that consequent
 *   malloc would immediately incur working set expansion);
 * - larger table has larger cache footprint, which can affect
 *   performance of other code paths (not necessarily even from same
 *   thread in Hyper-Threading world);
 *
 * Value of 1 is not appropriate for performance reasons.
 */

static void gcm_init_4bit(u128 Htable[16],
                          const uint64_t H[2]) {
    u128 V;
#if defined(OPENSSL_SMALL_FOOTPRINT)
    int i;
#endif

    Htable[0].hi = 0;
    Htable[0].lo = 0;
    V.hi = H[0];
    V.lo = H[1];

#if defined(OPENSSL_SMALL_FOOTPRINT)
    for(Htable[8] = V, i = 4; i > 0; i >>= 1) {
        REDUCE1BIT(V);
        Htable[i] = V;
    }

    for(i = 2; i < 16; i <<= 1) {
        u128* Hi = Htable + i;
        int j;
        for(V = *Hi, j = 1; j < i; ++j) {
            Hi[j].hi = V.hi ^ Htable[j].hi;
            Hi[j].lo = V.lo ^ Htable[j].lo;
        }
    }
#else
    Htable[8] = V;
    REDUCE1BIT(V);
    Htable[4] = V;
    REDUCE1BIT(V);
    Htable[2] = V;
    REDUCE1BIT(V);
    Htable[1] = V;
    Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
    V = Htable[4];
    Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
    Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
    Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
    V = Htable[8];
    Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
    Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
    Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
    Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
    Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
    Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
    Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;
#endif
}

#if !defined(GHASH_ASM) || defined(INCLUDE_C_GMULT_4BIT)
static const size_t rem_4bit[16] = {PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460), PACK(0x7080), PACK(0x6CA0),
                                    PACK(0x48C0), PACK(0x54E0), PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
                                    PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0)};

static void gcm_gmult_4bit(uint64_t Xi[2],
                           const u128 Htable[16]) {
    u128 Z;
    int cnt = 15;
    size_t rem, nlo, nhi;
    DECLARE_IS_ENDIAN;

    nlo = ((const uint8_t*)Xi)[15];
    nhi = nlo >> 4;
    nlo &= 0xf;

    Z.hi = Htable[nlo].hi;
    Z.lo = Htable[nlo].lo;

    while(1) {
        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if(sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (uint64_t)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nhi].hi;
        Z.lo ^= Htable[nhi].lo;

        if(--cnt < 0)
            break;

        nlo = ((const uint8_t*)Xi)[cnt];
        nhi = nlo >> 4;
        nlo &= 0xf;

        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if(sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (uint64_t)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nlo].hi;
        Z.lo ^= Htable[nlo].lo;
    }

    if(IS_LITTLE_ENDIAN) {
    #ifdef BSWAP8
        Xi[0] = BSWAP8(Z.hi);
        Xi[1] = BSWAP8(Z.lo);
    #else
        uint8_t* p = (uint8_t*)Xi;
        uint32_t v;
        v = (uint32_t)(Z.hi >> 32);
        PUTU32(p, v);
        v = (uint32_t)(Z.hi);
        PUTU32(p + 4, v);
        v = (uint32_t)(Z.lo >> 32);
        PUTU32(p + 8, v);
        v = (uint32_t)(Z.lo);
        PUTU32(p + 12, v);
    #endif
    } else {
        Xi[0] = Z.hi;
        Xi[1] = Z.lo;
    }
}

#endif

#if !defined(GHASH_ASM) || defined(INCLUDE_C_GHASH_4BIT)
    #if !defined(OPENSSL_SMALL_FOOTPRINT)
/*
 * Streamed gcm_mult_4bit, see CRYPTO_gcm128_[en|de]crypt for
 * details... Compiler-generated code doesn't seem to give any
 * performance improvement, at least not on x86[_64]. It's here
 * mostly as reference and a placeholder for possible future
 * non-trivial optimization[s]...
 */
static void gcm_ghash_4bit(uint64_t Xi[2],
                           const u128 Htable[16],
                           const uint8_t* inp,
                           size_t len) {
    u128 Z;
    int cnt;
    size_t rem, nlo, nhi;
    DECLARE_IS_ENDIAN;

    do {
        cnt = 15;
        nlo = ((const uint8_t*)Xi)[15];
        nlo ^= inp[15];
        nhi = nlo >> 4;
        nlo &= 0xf;

        Z.hi = Htable[nlo].hi;
        Z.lo = Htable[nlo].lo;

        while(1) {
            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if(sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (uint64_t)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nhi].hi;
            Z.lo ^= Htable[nhi].lo;

            if(--cnt < 0)
                break;

            nlo = ((const uint8_t*)Xi)[cnt];
            nlo ^= inp[cnt];
            nhi = nlo >> 4;
            nlo &= 0xf;

            rem = (size_t)Z.lo & 0xf;
            Z.lo = (Z.hi << 60) | (Z.lo >> 4);
            Z.hi = (Z.hi >> 4);
            if(sizeof(size_t) == 8)
                Z.hi ^= rem_4bit[rem];
            else
                Z.hi ^= (uint64_t)rem_4bit[rem] << 32;

            Z.hi ^= Htable[nlo].hi;
            Z.lo ^= Htable[nlo].lo;
        }

        if(IS_LITTLE_ENDIAN) {
        #ifdef BSWAP8
            Xi[0] = BSWAP8(Z.hi);
            Xi[1] = BSWAP8(Z.lo);
        #else
            uint8_t* p = (uint8_t*)Xi;
            uint32_t v;
            v = (uint32_t)(Z.hi >> 32);
            PUTU32(p, v);
            v = (uint32_t)(Z.hi);
            PUTU32(p + 4, v);
            v = (uint32_t)(Z.lo >> 32);
            PUTU32(p + 8, v);
            v = (uint32_t)(Z.lo);
            PUTU32(p + 12, v);
        #endif
        } else {
            Xi[0] = Z.hi;
            Xi[1] = Z.lo;
        }

        inp += 16;
        /* Block size is 128 bits so len is a multiple of 16 */
        len -= 16;
    } while(len > 0);
}
    #endif
#else
void gcm_gmult_4bit(uint64_t Xi[2],
                    const u128 Htable[16]);
void gcm_ghash_4bit(uint64_t Xi[2],
                    const u128 Htable[16],
                    const uint8_t* inp,
                    size_t len);
#endif

#define GCM_MUL(ctx) ctx->funcs.gmult(ctx->Xi.u, ctx->Htable)
#if defined(GHASH_ASM) || !defined(OPENSSL_SMALL_FOOTPRINT)
    #define GHASH(ctx, in, len) ctx->funcs.ghash((ctx)->Xi.u, (ctx)->Htable, in, len)
    /*
     * GHASH_CHUNK is "stride parameter" missioned to mitigate cache trashing
     * effect. In other words idea is to hash data while it's still in L1 cache
     * after encryption pass...
     */
    #define GHASH_CHUNK (3 * 1024)
#endif

static void gcm_get_funcs(struct gcm_funcs_st* ctx) {
    /* set defaults -- overridden below as needed */
    ctx->ginit = gcm_init_4bit;
#if !defined(GHASH_ASM)
    ctx->gmult = gcm_gmult_4bit;
#else
    ctx->gmult = NULL;
#endif
#if !defined(GHASH_ASM) && !defined(OPENSSL_SMALL_FOOTPRINT)
    ctx->ghash = gcm_ghash_4bit;
#else
    ctx->ghash = NULL;
#endif
}

void ossl_gcm_init_4bit(u128 Htable[16],
                        const uint64_t H[2]) {
    struct gcm_funcs_st funcs;

    gcm_get_funcs(&funcs);
    funcs.ginit(Htable, H);
}

void ossl_gcm_gmult_4bit(uint64_t Xi[2],
                         const u128 Htable[16]) {
    struct gcm_funcs_st funcs;

    gcm_get_funcs(&funcs);
    funcs.gmult(Xi, Htable);
}

void ossl_gcm_ghash_4bit(uint64_t Xi[2],
                         const u128 Htable[16],
                         const uint8_t* inp,
                         size_t len) {
    struct gcm_funcs_st funcs;
    uint64_t tmp[2];
    size_t i;

    gcm_get_funcs(&funcs);
    if(funcs.ghash != NULL) {
        funcs.ghash(Xi, Htable, inp, len);
    } else {
        /* Emulate ghash if needed */
        for(i = 0; i < len; i += 16) {
            memcpy(tmp, &inp[i], sizeof(tmp));
            Xi[0] ^= tmp[0];
            Xi[1] ^= tmp[1];
            funcs.gmult(Xi, Htable);
        }
    }
}

void CRYPTO_gcm128_init(GCM128_CONTEXT* ctx,
                        void* key,
                        block128_f block) {
    DECLARE_IS_ENDIAN;

    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->key = key;

    (*block)(ctx->H.c, ctx->H.c, key);

    if(IS_LITTLE_ENDIAN) {
        /* H is stored in host byte order */
#ifdef BSWAP8
        ctx->H.u[0] = BSWAP8(ctx->H.u[0]);
        ctx->H.u[1] = BSWAP8(ctx->H.u[1]);
#else
        uint8_t* p = ctx->H.c;
        uint64_t hi, lo;
        hi = (uint64_t)GETU32(p) << 32 | GETU32(p + 4);
        lo = (uint64_t)GETU32(p + 8) << 32 | GETU32(p + 12);
        ctx->H.u[0] = hi;
        ctx->H.u[1] = lo;
#endif
    }

    gcm_get_funcs(&ctx->funcs);
    ctx->funcs.ginit(ctx->Htable, ctx->H.u);
}

void CRYPTO_gcm128_setiv(GCM128_CONTEXT* ctx,
                         const unsigned char* iv,
                         size_t len) {
    DECLARE_IS_ENDIAN;
    unsigned int ctr;

    ctx->len.u[0] = 0; /* AAD length */
    ctx->len.u[1] = 0; /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    if(len == 12) {
        memcpy(ctx->Yi.c, iv, 12);
        ctx->Yi.c[12] = 0;
        ctx->Yi.c[13] = 0;
        ctx->Yi.c[14] = 0;
        ctx->Yi.c[15] = 1;
        ctr = 1;
    } else {
        size_t i;
        uint64_t len0 = len;

        /* Borrow ctx->Xi to calculate initial Yi */
        ctx->Xi.u[0] = 0;
        ctx->Xi.u[1] = 0;

        while(len >= 16) {
            for(i = 0; i < 16; ++i)
                ctx->Xi.c[i] ^= iv[i];
            GCM_MUL(ctx);
            iv += 16;
            len -= 16;
        }
        if(len) {
            for(i = 0; i < len; ++i)
                ctx->Xi.c[i] ^= iv[i];
            GCM_MUL(ctx);
        }
        len0 <<= 3;
        if(IS_LITTLE_ENDIAN) {
#ifdef BSWAP8
            ctx->Xi.u[1] ^= BSWAP8(len0);
#else
            ctx->Xi.c[8] ^= (uint8_t)(len0 >> 56);
            ctx->Xi.c[9] ^= (uint8_t)(len0 >> 48);
            ctx->Xi.c[10] ^= (uint8_t)(len0 >> 40);
            ctx->Xi.c[11] ^= (uint8_t)(len0 >> 32);
            ctx->Xi.c[12] ^= (uint8_t)(len0 >> 24);
            ctx->Xi.c[13] ^= (uint8_t)(len0 >> 16);
            ctx->Xi.c[14] ^= (uint8_t)(len0 >> 8);
            ctx->Xi.c[15] ^= (uint8_t)(len0);
#endif
        } else {
            ctx->Xi.u[1] ^= len0;
        }

        GCM_MUL(ctx);

        if(IS_LITTLE_ENDIAN)
#ifdef BSWAP4
            ctr = BSWAP4(ctx->Xi.d[3]);
#else
            ctr = GETU32(ctx->Xi.c + 12);
#endif
        else
            ctr = ctx->Xi.d[3];

        /* Copy borrowed Xi to Yi */
        ctx->Yi.u[0] = ctx->Xi.u[0];
        ctx->Yi.u[1] = ctx->Xi.u[1];
    }

    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;

    (*ctx->block)(ctx->Yi.c, ctx->EK0.c, ctx->key);
    ++ctr;
    if(IS_LITTLE_ENDIAN)
#ifdef BSWAP4
        ctx->Yi.d[3] = BSWAP4(ctr);
#else
        PUTU32(ctx->Yi.c + 12, ctr);
#endif
    else
        ctx->Yi.d[3] = ctr;
}

int CRYPTO_gcm128_aad(GCM128_CONTEXT* ctx,
                      const unsigned char* aad,
                      size_t len) {
    size_t i;
    unsigned int n;
    uint64_t alen = ctx->len.u[0];

    if(ctx->len.u[1])
        return -2;

    alen += len;
    if(alen > ((uint64_t)(1) << 61) || (sizeof(len) == 8 && alen < len))
        return -1;
    ctx->len.u[0] = alen;

    n = ctx->ares;
    if(n) {
        while(n && len) {
            ctx->Xi.c[n] ^= *(aad++);
            --len;
            n = (n + 1) % 16;
        }
        if(n == 0)
            GCM_MUL(ctx);
        else {
            ctx->ares = n;
            return 0;
        }
    }
#ifdef GHASH
    if((i = (len & (size_t)-16))) {
        GHASH(ctx, aad, i);
        aad += i;
        len -= i;
    }
#else
    while(len >= 16) {
        for(i = 0; i < 16; ++i)
            ctx->Xi.c[i] ^= aad[i];
        GCM_MUL(ctx);
        aad += 16;
        len -= 16;
    }
#endif
    if(len) {
        n = (unsigned int)len;
        for(i = 0; i < len; ++i)
            ctx->Xi.c[i] ^= aad[i];
    }

    ctx->ares = n;
    return 0;
}

int CRYPTO_gcm128_encrypt(GCM128_CONTEXT* ctx,
                          const unsigned char* in,
                          unsigned char* out,
                          size_t len) {
    DECLARE_IS_ENDIAN;
    unsigned int n, ctr, mres;
    size_t i;
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void* key = ctx->key;

    mlen += len;
    if(mlen > (((uint64_t)(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if(ctx->ares) {
        /* First call to encrypt finalizes GHASH(AAD) */
#if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
        if(len == 0) {
            GCM_MUL(ctx);
            ctx->ares = 0;
            return 0;
        }
        memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
        ctx->Xi.u[0] = 0;
        ctx->Xi.u[1] = 0;
        mres = sizeof(ctx->Xi);
#else
        GCM_MUL(ctx);
#endif
        ctx->ares = 0;
    }

    if(IS_LITTLE_ENDIAN)
#ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
#else
        ctr = GETU32(ctx->Yi.c + 12);
#endif
    else
        ctr = ctx->Yi.d[3];

    n = mres % 16;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if(16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            if(n) {
    #if defined(GHASH)
                while(n && len) {
                    ctx->Xn[mres++] = *(out++) = *(in++) ^ ctx->EKi.c[n];
                    --len;
                    n = (n + 1) % 16;
                }
                if(n == 0) {
                    GHASH(ctx, ctx->Xn, mres);
                    mres = 0;
                } else {
                    ctx->mres = mres;
                    return 0;
                }
    #else
                while(n && len) {
                    ctx->Xi.c[n] ^= *(out++) = *(in++) ^ ctx->EKi.c[n];
                    --len;
                    n = (n + 1) % 16;
                }
                if(n == 0) {
                    GCM_MUL(ctx);
                    mres = 0;
                } else {
                    ctx->mres = n;
                    return 0;
                }
    #endif
            }
    #if defined(STRICT_ALIGNMENT)
            if(((size_t)in | (size_t)out) % sizeof(size_t) != 0)
                break;
    #endif
    #if defined(GHASH)
            if(len >= 16 && mres) {
                GHASH(ctx, ctx->Xn, mres);
                mres = 0;
            }
        #if defined(GHASH_CHUNK)
            while(len >= GHASH_CHUNK) {
                size_t j = GHASH_CHUNK;

                while(j) {
                    size_t_aX* out_t = (size_t_aX*)out;
                    const size_t_aX* in_t = (const size_t_aX*)in;

                    (*block)(ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if(IS_LITTLE_ENDIAN)
            #ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
            #else
                        PUTU32(ctx->Yi.c + 12, ctr);
            #endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for(i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    j -= 16;
                }
                GHASH(ctx, out - GHASH_CHUNK, GHASH_CHUNK);
                len -= GHASH_CHUNK;
            }
        #endif
            if((i = (len & (size_t)-16))) {
                size_t j = i;

                while(len >= 16) {
                    size_t_aX* out_t = (size_t_aX*)out;
                    const size_t_aX* in_t = (const size_t_aX*)in;

                    (*block)(ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if(IS_LITTLE_ENDIAN)
        #ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
        #else
                        PUTU32(ctx->Yi.c + 12, ctr);
        #endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for(i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    len -= 16;
                }
                GHASH(ctx, out - j, j);
            }
    #else
            while(len >= 16) {
                size_t* out_t = (size_t*)out;
                const size_t* in_t = (const size_t*)in;

                (*block)(ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if(IS_LITTLE_ENDIAN)
        #ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
        #else
                    PUTU32(ctx->Yi.c + 12, ctr);
        #endif
                else
                    ctx->Yi.d[3] = ctr;
                for(i = 0; i < 16 / sizeof(size_t); ++i)
                    ctx->Xi.t[i] ^= out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                GCM_MUL(ctx);
                out += 16;
                in += 16;
                len -= 16;
            }
    #endif
            if(len) {
                (*block)(ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if(IS_LITTLE_ENDIAN)
    #ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
    #else
                    PUTU32(ctx->Yi.c + 12, ctr);
    #endif
                else
                    ctx->Yi.d[3] = ctr;
    #if defined(GHASH)
                while(len--) {
                    ctx->Xn[mres++] = out[n] = in[n] ^ ctx->EKi.c[n];
                    ++n;
                }
    #else
                while(len--) {
                    ctx->Xi.c[n] ^= out[n] = in[n] ^ ctx->EKi.c[n];
                    ++n;
                }
                mres = n;
    #endif
            }

            ctx->mres = mres;
            return 0;
        } while(0);
    }
#endif
    for(i = 0; i < len; ++i) {
        if(n == 0) {
            (*block)(ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            if(IS_LITTLE_ENDIAN)
#ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
#else
                PUTU32(ctx->Yi.c + 12, ctr);
#endif
            else
                ctx->Yi.d[3] = ctr;
        }
#if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
        ctx->Xn[mres++] = out[i] = in[i] ^ ctx->EKi.c[n];
        n = (n + 1) % 16;
        if(mres == sizeof(ctx->Xn)) {
            GHASH(ctx, ctx->Xn, sizeof(ctx->Xn));
            mres = 0;
        }
#else
        ctx->Xi.c[n] ^= out[i] = in[i] ^ ctx->EKi.c[n];
        mres = n = (n + 1) % 16;
        if(n == 0)
            GCM_MUL(ctx);
#endif
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_decrypt(GCM128_CONTEXT* ctx,
                          const unsigned char* in,
                          unsigned char* out,
                          size_t len) {
    DECLARE_IS_ENDIAN;
    unsigned int n, ctr, mres;
    size_t i;
    uint64_t mlen = ctx->len.u[1];
    block128_f block = ctx->block;
    void* key = ctx->key;

    mlen += len;
    if(mlen > (((uint64_t)(1) << 36) - 32) || (sizeof(len) == 8 && mlen < len))
        return -1;
    ctx->len.u[1] = mlen;

    mres = ctx->mres;

    if(ctx->ares) {
        /* First call to decrypt finalizes GHASH(AAD) */
#if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
        if(len == 0) {
            GCM_MUL(ctx);
            ctx->ares = 0;
            return 0;
        }
        memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
        ctx->Xi.u[0] = 0;
        ctx->Xi.u[1] = 0;
        mres = sizeof(ctx->Xi);
#else
        GCM_MUL(ctx);
#endif
        ctx->ares = 0;
    }

    if(IS_LITTLE_ENDIAN)
#ifdef BSWAP4
        ctr = BSWAP4(ctx->Yi.d[3]);
#else
        ctr = GETU32(ctx->Yi.c + 12);
#endif
    else
        ctr = ctx->Yi.d[3];

    n = mres % 16;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if(16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            if(n) {
    #if defined(GHASH)
                while(n && len) {
                    *(out++) = (ctx->Xn[mres++] = *(in++)) ^ ctx->EKi.c[n];
                    --len;
                    n = (n + 1) % 16;
                }
                if(n == 0) {
                    GHASH(ctx, ctx->Xn, mres);
                    mres = 0;
                } else {
                    ctx->mres = mres;
                    return 0;
                }
    #else
                while(n && len) {
                    uint8_t c = *(in++);
                    *(out++) = c ^ ctx->EKi.c[n];
                    ctx->Xi.c[n] ^= c;
                    --len;
                    n = (n + 1) % 16;
                }
                if(n == 0) {
                    GCM_MUL(ctx);
                    mres = 0;
                } else {
                    ctx->mres = n;
                    return 0;
                }
    #endif
            }
    #if defined(STRICT_ALIGNMENT)
            if(((size_t)in | (size_t)out) % sizeof(size_t) != 0)
                break;
    #endif
    #if defined(GHASH)
            if(len >= 16 && mres) {
                GHASH(ctx, ctx->Xn, mres);
                mres = 0;
            }
        #if defined(GHASH_CHUNK)
            while(len >= GHASH_CHUNK) {
                size_t j = GHASH_CHUNK;

                GHASH(ctx, in, GHASH_CHUNK);
                while(j) {
                    size_t_aX* out_t = (size_t_aX*)out;
                    const size_t_aX* in_t = (const size_t_aX*)in;

                    (*block)(ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if(IS_LITTLE_ENDIAN)
            #ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
            #else
                        PUTU32(ctx->Yi.c + 12, ctr);
            #endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for(i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    j -= 16;
                }
                len -= GHASH_CHUNK;
            }
        #endif
            if((i = (len & (size_t)-16))) {
                GHASH(ctx, in, i);
                while(len >= 16) {
                    size_t_aX* out_t = (size_t_aX*)out;
                    const size_t_aX* in_t = (const size_t_aX*)in;

                    (*block)(ctx->Yi.c, ctx->EKi.c, key);
                    ++ctr;
                    if(IS_LITTLE_ENDIAN)
        #ifdef BSWAP4
                        ctx->Yi.d[3] = BSWAP4(ctr);
        #else
                        PUTU32(ctx->Yi.c + 12, ctr);
        #endif
                    else
                        ctx->Yi.d[3] = ctr;
                    for(i = 0; i < 16 / sizeof(size_t); ++i)
                        out_t[i] = in_t[i] ^ ctx->EKi.t[i];
                    out += 16;
                    in += 16;
                    len -= 16;
                }
            }
    #else
            while(len >= 16) {
                size_t* out_t = (size_t*)out;
                const size_t* in_t = (const size_t*)in;

                (*block)(ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if(IS_LITTLE_ENDIAN)
        #ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
        #else
                    PUTU32(ctx->Yi.c + 12, ctr);
        #endif
                else
                    ctx->Yi.d[3] = ctr;
                for(i = 0; i < 16 / sizeof(size_t); ++i) {
                    size_t c = in_t[i];
                    out_t[i] = c ^ ctx->EKi.t[i];
                    ctx->Xi.t[i] ^= c;
                }
                GCM_MUL(ctx);
                out += 16;
                in += 16;
                len -= 16;
            }
    #endif
            if(len) {
                (*block)(ctx->Yi.c, ctx->EKi.c, key);
                ++ctr;
                if(IS_LITTLE_ENDIAN)
    #ifdef BSWAP4
                    ctx->Yi.d[3] = BSWAP4(ctr);
    #else
                    PUTU32(ctx->Yi.c + 12, ctr);
    #endif
                else
                    ctx->Yi.d[3] = ctr;
    #if defined(GHASH)
                while(len--) {
                    out[n] = (ctx->Xn[mres++] = in[n]) ^ ctx->EKi.c[n];
                    ++n;
                }
    #else
                while(len--) {
                    uint8_t c = in[n];
                    ctx->Xi.c[n] ^= c;
                    out[n] = c ^ ctx->EKi.c[n];
                    ++n;
                }
                mres = n;
    #endif
            }

            ctx->mres = mres;
            return 0;
        } while(0);
    }
#endif
    for(i = 0; i < len; ++i) {
        uint8_t c;
        if(n == 0) {
            (*block)(ctx->Yi.c, ctx->EKi.c, key);
            ++ctr;
            if(IS_LITTLE_ENDIAN)
#ifdef BSWAP4
                ctx->Yi.d[3] = BSWAP4(ctr);
#else
                PUTU32(ctx->Yi.c + 12, ctr);
#endif
            else
                ctx->Yi.d[3] = ctr;
        }
#if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
        out[i] = (ctx->Xn[mres++] = c = in[i]) ^ ctx->EKi.c[n];
        n = (n + 1) % 16;
        if(mres == sizeof(ctx->Xn)) {
            GHASH(ctx, ctx->Xn, sizeof(ctx->Xn));
            mres = 0;
        }
#else
        c = in[i];
        out[i] = c ^ ctx->EKi.c[n];
        ctx->Xi.c[n] ^= c;
        mres = n = (n + 1) % 16;
        if(n == 0)
            GCM_MUL(ctx);
#endif
    }

    ctx->mres = mres;
    return 0;
}

int CRYPTO_gcm128_finish(GCM128_CONTEXT* ctx,
                         const unsigned char* tag,
                         size_t len) {
    DECLARE_IS_ENDIAN;
    uint64_t alen = ctx->len.u[0] << 3;
    uint64_t clen = ctx->len.u[1] << 3;

#if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
    u128 bitlen;
    unsigned int mres = ctx->mres;

    if(mres) {
        unsigned blocks = (mres + 15) & -16;

        memset(ctx->Xn + mres, 0, blocks - mres);
        mres = blocks;
        if(mres == sizeof(ctx->Xn)) {
            GHASH(ctx, ctx->Xn, mres);
            mres = 0;
        }
    } else if(ctx->ares) {
        GCM_MUL(ctx);
    }
#else
    if(ctx->mres || ctx->ares)
        GCM_MUL(ctx);
#endif

    if(IS_LITTLE_ENDIAN) {
#ifdef BSWAP8
        alen = BSWAP8(alen);
        clen = BSWAP8(clen);
#else
        uint8_t* p = ctx->len.c;

        ctx->len.u[0] = alen;
        ctx->len.u[1] = clen;

        alen = (uint64_t)GETU32(p) << 32 | GETU32(p + 4);
        clen = (uint64_t)GETU32(p + 8) << 32 | GETU32(p + 12);
#endif
    }

#if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
    bitlen.hi = alen;
    bitlen.lo = clen;
    memcpy(ctx->Xn + mres, &bitlen, sizeof(bitlen));
    mres += sizeof(bitlen);
    GHASH(ctx, ctx->Xn, mres);
#else
    ctx->Xi.u[0] ^= alen;
    ctx->Xi.u[1] ^= clen;
    GCM_MUL(ctx);
#endif

    ctx->Xi.u[0] ^= ctx->EK0.u[0];
    ctx->Xi.u[1] ^= ctx->EK0.u[1];

    if(tag && len <= sizeof(ctx->Xi))
        return memcmp(ctx->Xi.c, tag, len);
    else
        return -1;
}

void CRYPTO_gcm128_tag(GCM128_CONTEXT* ctx,
                       unsigned char* tag,
                       size_t len) {
    CRYPTO_gcm128_finish(ctx, NULL, 0);
    memcpy(tag, ctx->Xi.c, len <= sizeof(ctx->Xi.c) ? len : sizeof(ctx->Xi.c));
}

GCM128_CONTEXT* CRYPTO_gcm128_new(void* key,
                                  block128_f block) {
    GCM128_CONTEXT* ret;

    if((ret = malloc(sizeof(*ret))) != NULL)
        CRYPTO_gcm128_init(ret, key, block);

    return ret;
}

void CRYPTO_gcm128_release(GCM128_CONTEXT* ctx) { free(ctx); }

// block128_f 타입에 맞는 래퍼 함수 정의
// block128_f는 일반적으로 void (*)(const unsigned char *, unsigned char *, const void *) 형태를 가집니다.
void aes_encrypt_wrapper(const unsigned char* in,
                         unsigned char* out,
                         const void* key_ptr) {
    // const void *key_ptr를 mg_aes_key * 타입으로 안전하게 캐스팅
    const mg_aes_key* aes_key = (const mg_aes_key*)key_ptr;

    // 실제 AES_encrypt 함수 호출
    AES_encrypt(in, out, aes_key);
}

// Private helper to setup GCM context and AES key
static int setup_gcm_context(mg_aes_gcm_ctx_t* ctx,
                             const unsigned char* key,
                             size_t key_len,
                             const unsigned char* iv,
                             size_t iv_len,
                             const unsigned char* aad,
                             size_t aad_len,
                             int is_encrypt) {
    if(key_len != 16 && key_len != 24 && key_len != 32) {
        return MG_GCM_ERROR_INVALID_KEY_LEN;
    }
    if(iv_len == 0 || iv_len > 16) { // Common IV lengths are 12-16 bytes
        return MG_GCM_ERROR_IV_LEN;
    }

    // Set AES key
    int aes_ret;
    if(is_encrypt) {
        aes_ret = AES_set_encrypt_key(key, key_len * 8, &ctx->aes_key);
    } else {
        aes_ret = AES_set_decrypt_key(key, key_len * 8, &ctx->aes_key);
    }
    if(aes_ret < 0) {                        // Assuming AES_set_key returns 0 on success, <0 on error
        return MG_GCM_ERROR_INVALID_KEY_LEN; // Or a more specific AES key error
    }

    // Initialize GCM context with the AES key and block function wrapper
    // ctx->gcm_ctx = CRYPTO_gcm128_new(&ctx->aes_key, (block128_f)AES_encrypt);
    ctx->gcm_ctx = CRYPTO_gcm128_new(&ctx->aes_key, (block128_f)aes_encrypt_wrapper);
    if(!ctx->gcm_ctx) {
        return MG_GCM_ERROR_CONTEXT_INIT;
    }

    // Set IV
    memcpy(ctx->iv, iv, iv_len); // Copy IV to context
    // Pad IV if less than 16 bytes for internal GCM use,
    // though CRYPTO_gcm128_setiv handles variable IV lengths.

    CRYPTO_gcm128_setiv(ctx->gcm_ctx, iv, iv_len);

    // Process AAD if provided
    if(aad && aad_len > 0) {
        if(CRYPTO_gcm128_aad(ctx->gcm_ctx, aad, aad_len) != 0) {
            CRYPTO_gcm128_release(ctx->gcm_ctx);
            return MG_GCM_ERROR_AAD;
        }
    }

    ctx->is_encrypt = is_encrypt;
    return MG_GCM_SUCCESS;
}

// Private helper to clean up GCM context
static void cleanup_gcm_context(mg_aes_gcm_ctx_t* ctx) {
    if(ctx->gcm_ctx) {
        CRYPTO_gcm128_release(ctx->gcm_ctx);
        ctx->gcm_ctx = NULL;
    }
    // Optionally wipe sensitive key data
    memset(&ctx->aes_key, 0, sizeof(mg_aes_key));
    memset(ctx->iv, 0, sizeof(ctx->iv));
    memset(ctx->tag, 0, sizeof(ctx->tag));
}

int mg_gcm_encrypt_file(const unsigned char* key,
                        size_t key_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        unsigned char* output_tag,
                        size_t output_tag_len,
                        FILE* input_file,
                        FILE* output_file) {
    mg_aes_gcm_ctx_t ctx;
    // ctx.gcm_ctx = NULL;
    unsigned char* in_buf = NULL;
    unsigned char* out_buf = NULL;
    size_t bytes_read;
    int ret = MG_GCM_SUCCESS;

    if(!input_file || !output_file || !output_tag || output_tag_len < 16) {
        return MG_GCM_ERROR_INVALID_PARAM;
    }

    in_buf = (unsigned char*)malloc(STREAM_BUFFER_SIZE);
    out_buf = (unsigned char*)malloc(STREAM_BUFFER_SIZE);
    if(!in_buf || !out_buf) {
        ret = MG_GCM_ERROR_BUFFER_ALLOC;
        goto cleanup;
    }

    ret = setup_gcm_context(&ctx, key, key_len, iv, iv_len, aad, aad_len, 1);
    if(ret != MG_GCM_SUCCESS) {
        goto cleanup;
    }

    while((bytes_read = fread(in_buf, 1, STREAM_BUFFER_SIZE, input_file)) > 0) {
        if(CRYPTO_gcm128_encrypt(ctx.gcm_ctx, in_buf, out_buf, bytes_read) != 0) {
            ret = MG_GCM_ERROR_ENCRYPT_FAILED;
            goto cleanup;
        }
        if(fwrite(out_buf, 1, bytes_read, output_file) != bytes_read) {
            ret = MG_GCM_ERROR_FILE_IO;
            goto cleanup;
        }
    }
    if(ferror(input_file)) {
        ret = MG_GCM_ERROR_FILE_IO;
        goto cleanup;
    }

    // // Finalize encryption and get tag
    // if (CRYPTO_gcm128_finish(ctx.gcm_ctx, NULL, 0) != 0) {
    // 	printf("gcmfinish\n");
    // 	// This should not happen for encryption unless internal error
    // 	ret = MG_GCM_ERROR_ENCRYPT_FAILED;
    // 	goto cleanup;
    // }
    CRYPTO_gcm128_tag(ctx.gcm_ctx, output_tag, output_tag_len);
    ctx.tag_len = output_tag_len;

cleanup:
    if(in_buf)
        free(in_buf);
    if(out_buf)
        free(out_buf);
    cleanup_gcm_context(&ctx);
    return ret;
}

int mg_gcm_decrypt_file(const unsigned char* key,
                        size_t key_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        const unsigned char* input_tag,
                        size_t input_tag_len,
                        FILE* input_file,
                        FILE* output_file) {
    mg_aes_gcm_ctx_t ctx;
    // ctx.gcm_ctx = NULL;
    unsigned char* in_buf = NULL;
    unsigned char* out_buf = NULL;
    size_t bytes_read;
    int ret = MG_GCM_SUCCESS;

    if(!input_file || !output_file || !input_tag || input_tag_len == 0) {
        return MG_GCM_ERROR_INVALID_PARAM;
    }
    if(input_tag_len > 16) { // GCM tag is typically 16 bytes max
        return MG_GCM_ERROR_TAG_LEN;
    }

    in_buf = (unsigned char*)malloc(STREAM_BUFFER_SIZE);
    out_buf = (unsigned char*)malloc(STREAM_BUFFER_SIZE);
    if(!in_buf || !out_buf) {
        ret = MG_GCM_ERROR_BUFFER_ALLOC;
        goto cleanup;
    }

    // key schedule은 encrypt와 동일하게 해야함
    ret = setup_gcm_context(&ctx, key, key_len, iv, iv_len, aad, aad_len, 1);
    if(ret != MG_GCM_SUCCESS) {
        goto cleanup;
    }

    while((bytes_read = fread(in_buf, 1, STREAM_BUFFER_SIZE, input_file)) > 0) {
        if(CRYPTO_gcm128_decrypt(ctx.gcm_ctx, in_buf, out_buf, bytes_read) != 0) {
            // Decryption update should not fail unless internal state is corrupted
            ret = MG_GCM_ERROR_DECRYPT_FAILED;
            goto cleanup;
        }
        if(fwrite(out_buf, 1, bytes_read, output_file) != bytes_read) {
            ret = MG_GCM_ERROR_FILE_IO;
            goto cleanup;
        }
    }
    if(ferror(input_file)) {
        ret = MG_GCM_ERROR_FILE_IO;
        goto cleanup;
    }

    // Finalize decryption and verify tag
    if(CRYPTO_gcm128_finish(ctx.gcm_ctx, input_tag, input_tag_len) != 0) {
        ret = MG_GCM_ERROR_TAG_MISMATCH; // Authentication failed
        goto cleanup;
    }

cleanup:
    if(in_buf)
        free(in_buf);
    if(out_buf)
        free(out_buf);
    cleanup_gcm_context(&ctx);
    return ret;
}