#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libbitcoinpqc/ml_dsa.h"

/*
 * This file implements the signing function for ML-DSA-44 (CRYSTALS-Dilithium)
 */

/* Include necessary headers from Dilithium reference implementation */
#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/randombytes.h"
#include "../../dilithium/ref/params.h"
#include "../../dilithium/ref/sign.h"
#include "../../dilithium/ref/fips202.h"

/* Debug mode flag - set to 0 to disable debug output */
#define ML_DSA_DEBUG 0

/* Conditional debug print macro */
#define DEBUG_PRINT(fmt, ...) \
    do { if (ML_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

/*
 * External declaration for the random data utilities
 * These are implemented in src/ml_dsa/utils.c
 */
extern void ml_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void ml_dsa_setup_custom_random(void);
extern void ml_dsa_restore_original_random(void);
extern void ml_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

static void secure_memzero(void* ptr, size_t len)
{
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static void ml_dsa_build_sign_seed(
    uint8_t seed_out[64],
    const uint8_t* m,
    size_t mlen,
    const uint8_t* sk,
    const uint8_t* random_data,
    size_t random_data_size
)
{
    uint8_t deterministic_seed[64];
    ml_dsa_derandomize(deterministic_seed, m, mlen, sk);

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

int ml_dsa_44_sign_with_randomness(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!sig || !siglen || !m || !sk) {
        fprintf(stderr, "ML-DSA sign: Invalid arguments\n");
        return -1;
    }

    DEBUG_PRINT("ML-DSA sign: Starting to sign message of length %zu\n", mlen);

    /* Hedged seed: H(H(sk||m) || random_data || m). Falls back to deterministic when random_data is absent. */
    uint8_t signing_seed[64];
    ml_dsa_build_sign_seed(signing_seed, m, mlen, sk, random_data, random_data_size);
    ml_dsa_init_random_source(signing_seed, sizeof(signing_seed));
    ml_dsa_setup_custom_random();
    DEBUG_PRINT("ML-DSA sign: Using hedged signing\n");

    /* Set up empty context */
    uint8_t ctx[1] = {0};
    size_t ctxlen = 0;

    /* Using fixed size buffer to avoid memory issues */
    uint8_t temp_sig[CRYPTO_BYTES + 1024]; /* Add some extra space for safety */
    size_t temp_siglen = 0;

    DEBUG_PRINT("ML-DSA sign: Calling crypto_sign_signature with CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

    /* Call the reference implementation's signing function */
    int result = crypto_sign_signature(temp_sig, &temp_siglen, m, mlen, ctx, ctxlen, sk);

    DEBUG_PRINT("ML-DSA sign: crypto_sign_signature returned %d, temp_siglen = %zu\n", result, temp_siglen);

    /* Restore original random bytes function if we changed it */
    ml_dsa_restore_original_random();
    secure_memzero(signing_seed, sizeof(signing_seed));

    /* Only copy the signature if it was successful */
    if (result == 0) {
        /* Double-check the signature size */
        if (temp_siglen > 0 && temp_siglen <= CRYPTO_BYTES) {
            /* Copy the signature to the output */
            memcpy(sig, temp_sig, temp_siglen);
            *siglen = temp_siglen;

            DEBUG_PRINT("ML-DSA sign: Signature copied successfully, size = %zu\n", *siglen);

            /* Debug: Print first few bytes of signature */
            DEBUG_PRINT("ML-DSA sign: Signature prefix: ");
            for (size_t i = 0; i < (temp_siglen < 8 ? temp_siglen : 8); i++) {
                if (ML_DSA_DEBUG) printf("%02x", sig[i]);
            }
            if (ML_DSA_DEBUG) printf("...\n");
        } else {
            fprintf(stderr, "ML-DSA sign: Invalid signature size: %zu\n", temp_siglen);
            return -1;
        }
    } else {
        fprintf(stderr, "ML-DSA sign: Signing failed with result: %d\n", result);
    }

    return result;
}

int ml_dsa_44_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    return ml_dsa_44_sign_with_randomness(sig, siglen, m, mlen, sk, NULL, 0);
}
