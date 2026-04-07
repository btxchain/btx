#ifndef SPX_FIPS202_H
#define SPX_FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

/*
 * Namespace all public FIPS-202 symbols so they do not collide with the
 * identically-named functions in other libraries (e.g. the ML-KEM copy in
 * bitcoin_crypto).  Every translation unit that includes this header --
 * both the implementation in fips202.c and all SPHINCS+ call-sites --
 * will transparently use the prefixed names.
 */
#define SPX_FIPS202_NAMESPACE(s) spx_fips202_##s

#define shake128_absorb        SPX_FIPS202_NAMESPACE(shake128_absorb)
#define shake128_squeezeblocks SPX_FIPS202_NAMESPACE(shake128_squeezeblocks)
#define shake128_inc_init      SPX_FIPS202_NAMESPACE(shake128_inc_init)
#define shake128_inc_absorb    SPX_FIPS202_NAMESPACE(shake128_inc_absorb)
#define shake128_inc_finalize  SPX_FIPS202_NAMESPACE(shake128_inc_finalize)
#define shake128_inc_squeeze   SPX_FIPS202_NAMESPACE(shake128_inc_squeeze)
#define shake256_absorb        SPX_FIPS202_NAMESPACE(shake256_absorb)
#define shake256_squeezeblocks SPX_FIPS202_NAMESPACE(shake256_squeezeblocks)
#define shake256_inc_init      SPX_FIPS202_NAMESPACE(shake256_inc_init)
#define shake256_inc_absorb    SPX_FIPS202_NAMESPACE(shake256_inc_absorb)
#define shake256_inc_finalize  SPX_FIPS202_NAMESPACE(shake256_inc_finalize)
#define shake256_inc_squeeze   SPX_FIPS202_NAMESPACE(shake256_inc_squeeze)
#define shake128               SPX_FIPS202_NAMESPACE(shake128)
#define shake256               SPX_FIPS202_NAMESPACE(shake256)
#define sha3_256_inc_init      SPX_FIPS202_NAMESPACE(sha3_256_inc_init)
#define sha3_256_inc_absorb    SPX_FIPS202_NAMESPACE(sha3_256_inc_absorb)
#define sha3_256_inc_finalize  SPX_FIPS202_NAMESPACE(sha3_256_inc_finalize)
#define sha3_256               SPX_FIPS202_NAMESPACE(sha3_256)
#define sha3_512_inc_init      SPX_FIPS202_NAMESPACE(sha3_512_inc_init)
#define sha3_512_inc_absorb    SPX_FIPS202_NAMESPACE(sha3_512_inc_absorb)
#define sha3_512_inc_finalize  SPX_FIPS202_NAMESPACE(sha3_512_inc_finalize)
#define sha3_512               SPX_FIPS202_NAMESPACE(sha3_512)

void shake128_absorb(uint64_t *s, const uint8_t *input, size_t inlen);

void shake128_squeezeblocks(uint8_t *output, size_t nblocks, uint64_t *s);

void shake128_inc_init(uint64_t *s_inc);
void shake128_inc_absorb(uint64_t *s_inc, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(uint64_t *s_inc);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, uint64_t *s_inc);

void shake256_absorb(uint64_t *s, const uint8_t *input, size_t inlen);
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, uint64_t *s);

void shake256_inc_init(uint64_t *s_inc);
void shake256_inc_absorb(uint64_t *s_inc, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(uint64_t *s_inc);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, uint64_t *s_inc);

void shake128(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen);

void shake256(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen);

void sha3_256_inc_init(uint64_t *s_inc);
void sha3_256_inc_absorb(uint64_t *s_inc, const uint8_t *input, size_t inlen);
void sha3_256_inc_finalize(uint8_t *output, uint64_t *s_inc);

void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);

void sha3_512_inc_init(uint64_t *s_inc);
void sha3_512_inc_absorb(uint64_t *s_inc, const uint8_t *input, size_t inlen);
void sha3_512_inc_finalize(uint8_t *output, uint64_t *s_inc);

void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);

#endif
