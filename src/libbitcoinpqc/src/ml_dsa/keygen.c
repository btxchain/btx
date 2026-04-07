#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/ml_dsa.h"

/*
 * This file implements the key generation function for ML-DSA-44 (CRYSTALS-Dilithium)
 */

/* Include necessary headers from Dilithium reference implementation */
#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/randombytes.h"
#include "../../dilithium/ref/params.h"
#include "../../dilithium/ref/sign.h"

/*
 * External declaration for the random data utilities
 * These are implemented in src/ml_dsa/utils.c
 */
extern void ml_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void ml_dsa_setup_custom_random(void);
extern void ml_dsa_restore_original_random(void);

int ml_dsa_44_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < 128) {
        return -1;
    }

    /* Set up custom random bytes function with user-provided entropy */
    ml_dsa_init_random_source(random_data, random_data_size);
    ml_dsa_setup_custom_random();

    /* Call the reference implementation's key generation function */
    int result = crypto_sign_keypair(pk, sk);

    /* Restore original random bytes function */
    ml_dsa_restore_original_random();

    return result;
}
