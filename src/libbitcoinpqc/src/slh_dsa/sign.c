#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"
#include <stdio.h>

/*
 * This file implements the signing function for SLH-DSA-Shake-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ implementation */
#if defined(SPHINCSPLUS_VARIANT_SHAKE_A64)
#include "../../sphincsplus/shake-a64/api.h"
#include "../../sphincsplus/shake-a64/randombytes.h"
#include "../../sphincsplus/shake-a64/params.h"
#include "../../sphincsplus/shake-a64/fips202.h"
#elif defined(SPHINCSPLUS_VARIANT_REF)
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/randombytes.h"
#include "../../sphincsplus/ref/params.h"
#include "../../sphincsplus/ref/fips202.h"
#else
#error "SPHINCS+ variant not configured"
#endif

/* Debug mode flag - set to 0 to disable debug output */
#define SLH_DSA_DEBUG 0

/* Conditional debug print macro */
#define DEBUG_PRINT(fmt, ...) \
    do { if (SLH_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

/*
 * External declaration for the random data utilities
 * These are implemented in src/slh_dsa/utils.c
 */
extern void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void slh_dsa_setup_custom_random(void);
extern void slh_dsa_restore_original_random(void);
extern void slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

static void secure_memzero(void* ptr, size_t len)
{
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static void slh_dsa_build_sign_seed(
    uint8_t seed_out[64],
    const uint8_t* m,
    size_t mlen,
    const uint8_t* sk,
    const uint8_t* random_data,
    size_t random_data_size
)
{
    uint8_t deterministic_seed[64];
    slh_dsa_derandomize(deterministic_seed, m, mlen, sk);

    if (random_data && random_data_size > 0) {
        const size_t input_size = sizeof(deterministic_seed) + random_data_size + mlen;
        uint8_t* input = (uint8_t*)malloc(input_size);
        if (input) {
            memcpy(input, deterministic_seed, sizeof(deterministic_seed));
            memcpy(input + sizeof(deterministic_seed), random_data, random_data_size);
            memcpy(input + sizeof(deterministic_seed) + random_data_size, m, mlen);
            shake256(seed_out, sizeof(deterministic_seed), input, input_size);
            secure_memzero(input, input_size);
            free(input);
        } else {
            memcpy(seed_out, deterministic_seed, sizeof(deterministic_seed));
        }
    } else {
        memcpy(seed_out, deterministic_seed, sizeof(deterministic_seed));
    }

    secure_memzero(deterministic_seed, sizeof(deterministic_seed));
}

int slh_dsa_shake_128s_sign_with_randomness(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!sig || !siglen || !m || !sk) {
        return -1;
    }

    DEBUG_PRINT("SLH-DSA sign: Starting to sign message of length %zu\n", mlen);

    /* Hedged seed: H(H(sk||m) || random_data || m). Falls back to deterministic when random_data is absent. */
    uint8_t signing_seed[64];
    slh_dsa_build_sign_seed(signing_seed, m, mlen, sk, random_data, random_data_size);
    slh_dsa_init_random_source(signing_seed, sizeof(signing_seed));
    slh_dsa_setup_custom_random();
    DEBUG_PRINT("SLH-DSA sign: Using hedged signing\n");

    /* The reference implementation prepends the message to the signature
     * but we want just the signature, so we need to use the detached API
     */
    int result = crypto_sign_signature(sig, siglen, m, mlen, sk);
    DEBUG_PRINT("SLH-DSA sign: signature result = %d, length = %zu\n", result, *siglen);

    /* Restore original random bytes function */
    slh_dsa_restore_original_random();
    secure_memzero(signing_seed, sizeof(signing_seed));

    return result;
}

int slh_dsa_shake_128s_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    return slh_dsa_shake_128s_sign_with_randomness(sig, siglen, m, mlen, sk, NULL, 0);
}
